/*  scan_adv_ext.c
 *
 *  Raspberry Pi + nRF52840 USB-dongle
 *  ─────────────────────────────────
 *  • Passive **extended** scanner for BORUS wearable
 *  • Periodic heartbeat broadcaster (legacy PDU via ext-adv cmds)
 *
 *  Compile:  gcc scan_adv_ext.c -o scan_adv_ext -lbluetooth -lssl -lcrypto
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <time.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>

/* ───────────────────── 1.  APPLICATION CONFIG ───────────────────────── */

static const char target_mac[] = "EE:93:96:3C:66:B5";   /* BORUS wearable */

#define BASE_ADV_INTERVAL_S      60
#define JITTER_S                 5
#define ADV_BURST_DURATION_MS   3000
#define BORUS_COMPANY_ID      0x0059
#define TIME_FIELD_UNIT_MS       10

#define SENSOR_ADV_PAYLOAD_TYPE  0x00
#define AWAY_ADV_PAYLOAD_TYPE    0x01

#define SENSOR_DATA_PACKET_SIZE  229
#define NONCE_LEN                 8
#define SENSOR_PAYLOAD_DATA_LEN  (NONCE_LEN + SENSOR_DATA_PACKET_SIZE)
#define SYNC_REQ_PAYLOAD_DATA_LEN 2

#define TEMPERATURE_LOW_LIMIT    30
#define PRESSURE_BASE_HPA_X10 8500
#define MAX_IMU_SAMPLES_IN_PACKET   14

#ifndef EVT_LE_EXTENDED_ADVERTISING_REPORT
#define EVT_LE_EXTENDED_ADVERTISING_REPORT 0x0D
#endif

#ifndef le16_to_cpu
#define le16_to_cpu(x) btohs((x))
#endif

static const unsigned char aes_key[16] = {
    0x9F,0x7B,0x25,0xA0,0x68,0x52,0x33,0x1C,
    0x10,0x42,0x5E,0x71,0x99,0x84,0xC7,0xDD};

#define RPI_SAFETY_MARGIN_MS   500

/* ─────────── 2.  GLOBALS & TIMERS ───────────────────────────────────── */

static volatile sig_atomic_t shutdown_requested   = 0;
static volatile sig_atomic_t trigger_ap_burst_now = 0;

static struct itimerval next_burst_timer;
static time_t next_regular_burst_epoch = 0;

static int device = -1;                          /* HCI socket handle    */

/* ─────────── 3.  HCI COMMAND DEFINITIONS ────────────────────────────── */

#ifndef OCF_LE_SET_EXT_ADV_PARAMS   /* for older bluez headers */
#define OCF_LE_SET_EXT_ADV_PARAMS   0x0036
#define OCF_LE_SET_EXT_ADV_DATA     0x0037
#define OCF_LE_SET_EXT_ADV_ENABLE   0x0039
#define OCF_LE_SET_EXT_SCAN_PARAMS  0x0041
#define OCF_LE_SET_EXT_SCAN_ENABLE  0x0042
#endif

#define LE_SCAN_PHY_1M   0x01

#define UINT24_TO_ARRAY(v, a)  do{ (a)[0]=(v)&0xFF; (a)[1]=((v)>>8)&0xFF; (a)[2]=((v)>>16)&0xFF; }while(0)

/* Extended-adv parameter CP ------------------------------------------- */
typedef struct __attribute__((packed)) {
    uint8_t  handle;
    uint16_t evt_prop;
    uint8_t  prim_int_min[3];
    uint8_t  prim_int_max[3];
    uint8_t  prim_chn_map;
    uint8_t  own_addr_type;
    uint8_t  peer_addr_type;
    bdaddr_t peer_addr;
    uint8_t  adv_filt_policy;
    int8_t   adv_tx_power;
    uint8_t  prim_adv_phy;
    uint8_t  sec_adv_max_skip;
    uint8_t  sec_adv_phy;
    uint8_t  adv_sid;
    uint8_t  scan_req_notif;
} le_set_ext_adv_params_cp;

/* Extended-adv data CP ------------------------------------------------- */
typedef struct __attribute__((packed)) {
    uint8_t handle;
    uint8_t operation;
    uint8_t frag_pref;
    uint8_t data_len;
    uint8_t data[251];
} le_set_ext_adv_data_cp;

/* Extended-adv enable CP ---------------------------------------------- */
typedef struct __attribute__((packed)) {
    uint8_t enable;
    uint8_t num_sets;
    struct __attribute__((packed)) {
        uint8_t  handle;
        uint16_t duration;
        uint8_t  max_ext_adv_evts;
    } set[1];
} le_set_ext_adv_enable_cp;

/* Extended-scan parameter CP ------------------------------------------ */
typedef struct __attribute__((packed)) {
    uint8_t  own_addr_type;
    uint8_t  scanning_filter_policy;
    uint8_t  scanning_phys;          /* bit-field */
    struct __attribute__((packed)) { /* settings for PHY 1M only          */
        uint8_t  scan_type;
        uint16_t scan_interval;
        uint16_t scan_window;
    } phy_1m;
} le_set_ext_scan_params_cp;

/* Extended-scan enable CP --------------------------------------------- */
typedef struct __attribute__((packed)) {
    uint8_t  enable;
    uint8_t  filter_dup;
    uint16_t duration;   /* 0 = no limit */
    uint16_t period;     /* 0 = no periodic scan */
} le_set_ext_scan_enable_cp;

/* Build generic HCI request */
static struct hci_request hci_req(uint16_t ocf,int clen,void *status,void *cp)
{
    struct hci_request rq={0};
    rq.ogf    = OGF_LE_CTL;
    rq.ocf    = ocf;
    rq.cparam = cp;
    rq.clen   = clen;
    rq.rparam = status;
    rq.rlen   = 1;
    return rq;
}

/* ─────────── 4.  EXT-ADVERTISER HELPERS ────────────────────────────── */

static int set_static_adv_addr(int dev, const char *str_addr)
{
    bdaddr_t a;
    uint8_t status;

    if (str2ba(str_addr, &a) < 0)
    {
        fprintf(stderr, "bad addr %s\n", str_addr);
        return -1;
    }

    uint8_t cp[6];
    for (int i = 0; i < 6; i++)
    {
        cp[i] = a.b[i];
    }

    struct hci_request rq = {
        .ogf = OGF_LE_CTL,
        .ocf = OCF_LE_SET_RANDOM_ADDRESS,
        .cparam = cp,
        .clen = sizeof(cp),
        .rparam = &status,
        .rlen = 1
    };
    
    if (hci_send_req(dev, &rq, 1000) < 0)
    {
        return -1;
    }

    if (status)
    {
        errno = EIO;
        return -1;
    }
    
    return 0;
}

static int set_ext_adv_params(int dev)
{
    le_set_ext_adv_params_cp cp={0};
    cp.handle   = 0x00;
    cp.evt_prop = htobs(0x0010 | 0x0002); /* legacy PDU, non-scan, non-conn */
    UINT24_TO_ARRAY(0x0050, cp.prim_int_min);   /* 100 ms */
    UINT24_TO_ARRAY(0x0052, cp.prim_int_max);   /* 150 ms */
    cp.prim_chn_map  = 0x07;
    cp.own_addr_type = 0x01;
    cp.adv_tx_power  = 0x7F;
    cp.prim_adv_phy  = 0x01;
    cp.sec_adv_phy   = 0x01;

    uint8_t st;
    struct hci_request rq=hci_req(OCF_LE_SET_EXT_ADV_PARAMS,sizeof(cp),&st,&cp);
    if(hci_send_req(dev,&rq,1000)<0||st){fprintf(stderr,"ext adv param fail 0x%02X\n",st);return -1;}
    return 0;
}

static int set_ext_adv_data_time(int dev,uint16_t time_cs)
{
    le_set_ext_adv_data_cp cp={0};
    cp.handle    = 0x00;
    cp.operation = 0x03;            /* complete data */
    cp.frag_pref = 0x00;
    uint8_t *d=cp.data;
    *d++=0x05; *d++=0xFF; *d++=0x59; *d++=0x00;
    *d++=(uint8_t)(time_cs & 0xFF); *d++=(uint8_t)(time_cs>>8);
    cp.data_len=d-cp.data;

    uint8_t st;
    struct hci_request rq=hci_req(OCF_LE_SET_EXT_ADV_DATA,4+cp.data_len,&st,&cp);
    if(hci_send_req(dev,&rq,1000)<0||st){fprintf(stderr,"ext adv data fail 0x%02X\n",st);return -1;}
    return 0;
}

static int set_ext_adv_enable(int dev,bool en)
{
    le_set_ext_adv_enable_cp cp={0};
    cp.enable   = en?1:0;
    cp.num_sets = 1;
    cp.set[0].handle = 0x00;

    uint8_t st;
    struct hci_request rq=hci_req(OCF_LE_SET_EXT_ADV_ENABLE,sizeof(cp),&st,&cp);
    if(hci_send_req(dev,&rq,1000)<0||st){fprintf(stderr,"ext adv %s fail 0x%02X\n",en?"en":"dis",st);return -1;}
    return 0;
}

/* ─────────── 5.  EXT-SCANNER HELPERS ───────────────────────────────── */

static int set_ext_scan_params(int dev)
/* passive scan, 1 M PHY, 10 ms window */
{
    le_set_ext_scan_params_cp cp={0};
    cp.own_addr_type          = 0x00;
    cp.scanning_filter_policy = 0x00;
    cp.scanning_phys          = LE_SCAN_PHY_1M;
    cp.phy_1m.scan_type       = 0x00;          /* passive */
    cp.phy_1m.scan_interval   = htobs(0x0010); /* 10 ms  */
    cp.phy_1m.scan_window     = htobs(0x0010); /* 10 ms  */

    uint8_t st;
    struct hci_request rq=hci_req(OCF_LE_SET_EXT_SCAN_PARAMS,sizeof(cp),&st,&cp);
    if(hci_send_req(dev,&rq,1000)<0||st){fprintf(stderr,"ext scan param fail 0x%02X\n",st);return -1;}
    return 0;
}

static int set_ext_scan_enable(int dev,bool en,bool filter_dup)
{
    le_set_ext_scan_enable_cp cp={0};
    cp.enable     = en?1:0;
    cp.filter_dup = filter_dup?1:0;  /* 0=disable,1=enable */
    cp.duration   = 0;               /* continuous */
    cp.period     = 0;

    uint8_t st;
    struct hci_request rq=hci_req(OCF_LE_SET_EXT_SCAN_ENABLE,sizeof(cp),&st,&cp);
    if(hci_send_req(dev,&rq,1000)<0||st){fprintf(stderr,"ext scan %s fail 0x%02X\n",en?"en":"dis",st);return -1;}
    return 0;
}

/* ─────────── 6.  AES-CTR DECRYPT (unchanged) ───────────────────────── */

static int decrypt_sensor_block_ap(const unsigned char *key,
                                   const uint8_t *nonce,
                                   const uint8_t *cipher,
                                   uint8_t *plain)
{
    EVP_CIPHER_CTX *ctx=NULL; int len=0,plen=0,ret=0;
    unsigned char iv[AES_BLOCK_SIZE]={0}; memcpy(iv,nonce,NONCE_LEN);

    ctx=EVP_CIPHER_CTX_new();
    if(!ctx){ret=-1;goto done;}
    if(1!=EVP_DecryptInit_ex(ctx,EVP_aes_128_ctr(),NULL,key,iv)){ret=-2;goto done;}
    if(1!=EVP_DecryptUpdate(ctx,plain,&len,cipher,SENSOR_DATA_PACKET_SIZE)){ret=-3;goto done;}
    plen=len;
    if(1!=EVP_DecryptFinal_ex(ctx,plain+len,&len)){ret=-4;goto done;}
    plen+=len;
    ret=(plen==SENSOR_DATA_PACKET_SIZE)?0:-5;
done:
    if(ret) ERR_print_errors_fp(stderr);
    if(ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* ─────────── 7.  SIGNALS & TIMERS ───────────────────────────────────── */

static void term_handler(int s){(void)s;shutdown_requested=1;}
static void alarm_handler(int s){(void)s;trigger_ap_burst_now=1;}

static int schedule_ap_burst(long sec,long usec)
{
    struct itimerval tv = { .it_value = { .tv_sec=sec,.tv_usec=usec }};
    return setitimer(ITIMER_REAL,&tv,NULL);
}

static uint16_t time_to_next_cs(void)
{
    struct timeval tv; gettimeofday(&tv,NULL);
    uint64_t now=(uint64_t)tv.tv_sec*1000000ULL+tv.tv_usec;
    uint64_t next=(uint64_t)next_regular_burst_epoch*1000000ULL;
    if(next<=now) return 0;
    uint64_t dcs=(next-now+9999ULL)/10000ULL;
    return dcs>0xFFFF?0xFFFF:(uint16_t)dcs;
}

/* ─────────── 8.  PROCESS EXTENDED ADV REPORTS  ─────────────────────── */

#define MAX_ADV_BUF 260   /* 229 + 15 + safety */

typedef struct {
    bdaddr_t addr;
    uint8_t  sid;
    int      len;
    uint8_t  data[MAX_ADV_BUF];
} adv_acc_t;

/* ------------------------------------------------------------------ */
/*  process_scan_packet() -- reassemble two fragments and debug print */
/* ------------------------------------------------------------------ */
static void process_scan_packet(uint8_t *buf, int len)
{
    /* ---------- static re-assembly state (only one BORUS device) ---- */
    static uint8_t  acc_data[260];
    static int      acc_len = 0;
    static bdaddr_t acc_addr = {{0}};
    static uint8_t  acc_sid  = 0xFF;

    if (len < HCI_EVENT_HDR_SIZE + 1 + EVT_LE_META_EVENT_SIZE)
        return;

    evt_le_meta_event *me = (void *)(buf + HCI_EVENT_HDR_SIZE + 1);
    if (me->subevent != EVT_LE_EXTENDED_ADVERTISING_REPORT)
        return;

    uint8_t reports = me->data[0];
    uint8_t *rp     = me->data + 1;

    while (reports--) {
        /* --- fixed header ------------------------------------------ */
        uint16_t evt_type = le16_to_cpu(*(uint16_t *)rp);  rp += 2;
        uint8_t  addr_type = *rp++;
        bdaddr_t addr;  memcpy(&addr, rp, 6);  rp += 6;
        uint8_t  prim_phy = *rp++, sec_phy = *rp++, sid = *rp++;
        int8_t   tx_pwr = *rp++,  rssi    = *rp++;
        rp += 2      /* periodic int */ + 1 + 6;  /* dir addr */
        uint8_t adv_len = *rp++;

        uint8_t *adv = rp;  rp += adv_len;

        /* only care about our BORUS MAC */
        char addr_str[18];  ba2str(&addr, addr_str);
        if (strcmp(addr_str, target_mac))
            continue;

        /* ---------- DEBUG: show fragment info ---------------------- */
        struct timeval tv; gettimeofday(&tv, NULL);
        printf("%ld.%06ld  RSSI %d  SID %u  dataStatus=%u  len=%u\n",
               (long)tv.tv_sec, (long)tv.tv_usec,
               rssi, sid, (evt_type >> 13) & 0x03, adv_len);

        /* ---------- (re)start accumulator if new addr/SID ---------- */
        if (bacmp(&addr, &acc_addr) || sid != acc_sid) {
            acc_addr = addr;
            acc_sid  = sid;
            acc_len  = 0;
        }

        if (acc_len + adv_len > sizeof(acc_data))   /* shouldn't happen */
            acc_len = 0;

        memcpy(acc_data + acc_len, adv, adv_len);
        acc_len += adv_len;

        /* need at least 2 bytes to read first AD header */
        if (acc_len < 2)
            continue;

        uint8_t field_len  = acc_data[0];
        uint8_t field_type = acc_data[1];

        /* wait until the whole Manufacturer block (len+1 bytes) is present */
        if (field_type != 0xFF || acc_len < field_len + 1)
            continue;

        /* ---------- DEBUG: dump first 10 bytes of manufacturer ----- */
        printf("  Manufacturer block complete (%u bytes). First 10: ",
               field_len);
        for (int i = 0; i < 10 && i < field_len - 1; i++)
            printf("%02x ", acc_data[2 + i]);
        printf("\n");

        /*  Now parse manufacturer payload --------------------------- */
        uint8_t *pay_start = &acc_data[2];   // This is custom type | nonce | sensor data       
        uint8_t pay_len = field_len - 1;    // This is the length of custom type | nonce | sensor data

        uint8_t  ptype   = pay_start[0];    // This is custom type
        uint8_t *payload = &pay_start[1];   // This is nonce | sensor data
        uint16_t plen    = pay_len - 1;     // This is the length of nonce | sensor data
        
        uint8_t *nonce = payload;
        uint16_t cid = (nonce[0]) | (nonce[1] << 8);
        if (cid != BORUS_COMPANY_ID && ptype == SENSOR_ADV_PAYLOAD_TYPE) {
            printf("  CID mismatch (0x%04X) skipping\n", cid);
            acc_len = 0;
            continue;
        }

        printf("  ptype=%u  plen=%u\n", ptype, plen);

        if (ptype == SENSOR_ADV_PAYLOAD_TYPE &&
            plen  == SENSOR_PAYLOAD_DATA_LEN) {
            
            uint8_t plain[SENSOR_DATA_PACKET_SIZE]; 
            if (decrypt_sensor_block_ap(aes_key, payload,
                                        payload + NONCE_LEN,
                                        plain) == 0) {
                /*  ── your original plaintext parsing routine ──       */
                
                int off = 0;

                // Temperature 
                uint8_t encT = plain[off++];
                int tempC = (int)encT - TEMPERATURE_LOW_LIMIT;
                
                // Pressure 
                uint16_t po;  
                memcpy(&po, &plain[off], 2);  
                off += 2;
                float press = (po + PRESSURE_BASE_HPA_X10) / 10.0f;
                
                // Battery 
                uint8_t batt = plain[off++];
                
                // Number of IMU batch
                uint8_t number_of_batch = plain[off++];
                
                // IMU Batch
                typedef struct {
                    int16_t v[6];
                    uint32_t ts;
                } imu_payload_t;

                imu_payload_t samples[MAX_IMU_SAMPLES_IN_PACKET]; 

                if (number_of_batch > MAX_IMU_SAMPLES_IN_PACKET)
                {
                    number_of_batch = MAX_IMU_SAMPLES_IN_PACKET;
                }

                for (uint8_t i = 0; i < number_of_batch; i++)
                {
                    memcpy(samples[i].v, &plain[off], 12);
                    off += 12;
                    memcpy(&samples[i].ts, &plain[off], 4);
                    off += 4; 
                }
                
                // printf("  DECRYPT OK  temp=%dC  press=%.1fhPa  batt=%u%%  samples=%u\n",
                //        tempC, press, batt, number_of_batch);
                
                for (uint8_t i = 0; i < number_of_batch; i++)
                {
                    // printf("    #%02u   ts=%u   ACC[%.2f, %.2f, %.2f]   GYR[%.2f, %.2f, %.2f]\n",
                    // i,
                    // samples[i].ts, 
                    // samples[i].v[0]/100.0f, samples[i].v[1]/100.0f, samples[i].v[2]/100.0f,
                    // samples[i].v[3]/100.0f, samples[i].v[4]/100.0f, samples[i].v[5]/100.0f); 
                }
            } else {
                printf("  Decrypt FAILED\n");
            }
        } else if (ptype == AWAY_ADV_PAYLOAD_TYPE && plen == SYNC_REQ_PAYLOAD_DATA_LEN)
        {
            uint16_t delay_s = payload[0] | (payload[1] << 8);
            printf("SYNC-REQ wearable scans in %u s\n", delay_s);

            long trig_us = (long)delay_s * 1000000L - (long)RPI_SAFETY_MARGIN_MS * 1000L;
            if (trig_us < 50000)
            {
                trig_us = 50000;
            }

            schedule_ap_burst(trig_us / 1000000L, trig_us % 1000000L);
        }
        
        /*  reset accumulator for next advertising event               */
        acc_len = 0;
    }
}


/* ─────────── 9.  MAIN LOOP ─────────────────────────────────────────── */

int main(void)
{
    srand(time(NULL));
    signal(SIGINT,  term_handler);
    signal(SIGTERM, term_handler);
    signal(SIGALRM, alarm_handler);

    device=hci_open_dev(1); if(device<0) device=hci_open_dev(0);
    if(device<0){perror("hci_open_dev");return 1;}
    int fl=fcntl(device,F_GETFL,0); fcntl(device,F_SETFL,fl|O_NONBLOCK);

    if (set_static_adv_addr(device, "C2:0D:8E:96:F8:23") < 0)
    {
        perror("Set random static addr");
        goto exit; 
    }
    
    if(set_ext_adv_params(device)<0)  goto exit;
    if(set_ext_scan_params(device)<0) goto exit;
    
    struct hci_filter flt; hci_filter_clear(&flt);
    hci_filter_set_ptype(HCI_EVENT_PKT,&flt);
    hci_filter_set_event(EVT_LE_META_EVENT,&flt);
    setsockopt(device,SOL_HCI,HCI_FILTER,&flt,sizeof(flt));

    int intv=BASE_ADV_INTERVAL_S+(rand()%(JITTER_S+1));
    next_regular_burst_epoch=time(NULL)+intv;
    schedule_ap_burst(intv,0);

    bool scanning=false, advertising=false;

    while(!shutdown_requested)
    {
        if(trigger_ap_burst_now)
        {
            trigger_ap_burst_now=0;

            printf("===================== AP burst TIMER fired: start advertising ==================== \n"); 

            int tcs=time_to_next_cs();
            if(scanning){ set_ext_scan_enable(device,false,false); scanning=false; usleep(50000);}
            set_ext_adv_data_time(device,(uint16_t)tcs);
            set_ext_adv_enable(device,true); advertising=true;
            usleep(ADV_BURST_DURATION_MS*1000);
            set_ext_adv_enable(device,false); advertising=false;

            printf("==================== AP burst Finished (%.1f s) ===================== \n", 
                ADV_BURST_DURATION_MS / 1000.0); 

            intv=BASE_ADV_INTERVAL_S+(rand()%(JITTER_S+1));
            next_regular_burst_epoch=time(NULL)+intv;
            schedule_ap_burst(intv,0);
            usleep(50000);
        }

        if(!scanning && !advertising)
        {
            if(set_ext_scan_enable(device,true,false)==0) scanning=true;
            else { perror("scan enable"); sleep(1);}
        }

        if(scanning)
        {
            uint8_t buf[HCI_MAX_EVENT_SIZE];
            while(scanning)
            {
                int n=read(device,buf,sizeof(buf));
                if(n<0){ if(errno==EAGAIN) break;
                         perror("read"); set_ext_scan_enable(device,false,false); scanning=false; break; }
                else if(n>0) process_scan_packet(buf,n);
                else break;
            }
        }
        usleep(1000);
    }

exit:
    schedule_ap_burst(0,0);
    set_ext_scan_enable(device,false,false);
    set_ext_adv_enable(device,false);
    if(device>=0) hci_close_dev(device);
    return 0;
}
