/*  scan_adv_ext.c
 *
 *  Raspberry Pi + nRF52840 USB-dongle
 *  ─────────────────────────────────
 *  • Passive **extended** scanner for BORUS wearable
 *  • Periodic heartbeat broadcaster (legacy PDU via ext-adv cmds)
 *  • Publishes JSON data to a MQTT broker
 *
 *  Compile:  cc scan_adv.c -o ~/scan_publish -lbluetooth -lssl -lcrypto -lmosquitto
 * 
 *  Usage:    sudo ~/scan_publish [hci_index] 
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
#include <mosquitto.h>

/* ───────────────────── 1.  APPLICATION CONFIG ───────────────────────── */

static const char target_mac[] = "EE:54:52:53:00:00"; /* BORUS wearable */
static const char random_ble_addr[] = "C0:54:52:53:00:00";

#define BROKER_ADDR "192.168.88.251"
#define BROKER_PORT 1883
#define MQTT_TOPIC "borus/wearable"

#define ADV_BURST_DURATION_MS 3000
#define BORUS_COMPANY_ID 0x0059

#define SENSOR_ADV_PAYLOAD_TYPE 0x00
#define AWAY_ADV_PAYLOAD_TYPE 0x01

#define SENSOR_DATA_PACKET_SIZE 231
#define NONCE_LEN 8
#define SENSOR_PAYLOAD_DATA_LEN (NONCE_LEN + SENSOR_DATA_PACKET_SIZE)
#define SYNC_REQ_PAYLOAD_DATA_LEN 2

#define TEMPERATURE_LOW_LIMIT 30
#define PRESSURE_BASE_HPA_X10 8500
#define MAX_IMU_SAMPLES_IN_PACKET 14

#ifndef EVT_LE_EXTENDED_ADVERTISING_REPORT
#define EVT_LE_EXTENDED_ADVERTISING_REPORT 0x0D
#endif

#ifndef le16_to_cpu
#define le16_to_cpu(x) btohs((x))
#endif

static const unsigned char aes_key[16] = {
    0x9F, 0x7B, 0x25, 0xA0, 0x68, 0x52, 0x33, 0x1C,
    0x10, 0x42, 0x5E, 0x71, 0x99, 0x84, 0xC7, 0xDD};

#define RPI_SAFETY_MARGIN_MS 500

/* ─────────── 2.  GLOBALS & TIMERS ───────────────────────────────────── */

static volatile sig_atomic_t shutdown_requested = 0;
static volatile sig_atomic_t trigger_ap_burst_now = 0;

static time_t next_regular_burst_epoch = 0;

static int device = -1; /* HCI socket handle    */

static struct mosquitto *mq = NULL;

/* ─────────── 3.  HCI COMMAND DEFINITIONS ────────────────────────────── */

#ifndef OCF_LE_SET_EXT_ADV_PARAMS /* for older bluez headers */
#define OCF_LE_SET_EXT_ADV_PARAMS 0x0036
#define OCF_LE_SET_EXT_ADV_DATA 0x0037
#define OCF_LE_SET_EXT_ADV_ENABLE 0x0039
#define OCF_LE_SET_EXT_SCAN_PARAMS 0x0041
#define OCF_LE_SET_EXT_SCAN_ENABLE 0x0042
#endif

#define LE_SCAN_PHY_1M 0x01

#define UINT24_TO_ARRAY(v, a)        \
    do                               \
    {                                \
        (a)[0] = (v) & 0xFF;         \
        (a)[1] = ((v) >> 8) & 0xFF;  \
        (a)[2] = ((v) >> 16) & 0xFF; \
    } while (0)

/* Extended-adv parameter CP ------------------------------------------- */
typedef struct __attribute__((packed))
{
    uint8_t handle;
    uint16_t evt_prop;
    uint8_t prim_int_min[3];
    uint8_t prim_int_max[3];
    uint8_t prim_chn_map;
    uint8_t own_addr_type;
    uint8_t peer_addr_type;
    bdaddr_t peer_addr;
    uint8_t adv_filt_policy;
    int8_t adv_tx_power;
    uint8_t prim_adv_phy;
    uint8_t sec_adv_max_skip;
    uint8_t sec_adv_phy;
    uint8_t adv_sid;
    uint8_t scan_req_notif;
} le_set_ext_adv_params_cp;

/* Extended-adv data CP ------------------------------------------------- */
typedef struct __attribute__((packed))
{
    uint8_t handle;
    uint8_t operation;
    uint8_t frag_pref;
    uint8_t data_len;
    uint8_t data[251];
} le_set_ext_adv_data_cp;

/* Extended-adv enable CP ---------------------------------------------- */
typedef struct __attribute__((packed))
{
    uint8_t enable;
    uint8_t num_sets;
    struct __attribute__((packed))
    {
        uint8_t handle;
        uint16_t duration;
        uint8_t max_ext_adv_evts;
    } set[1];
} le_set_ext_adv_enable_cp;

/* Extended-scan parameter CP ------------------------------------------ */
typedef struct __attribute__((packed))
{
    uint8_t own_addr_type;
    uint8_t scanning_filter_policy;
    uint8_t scanning_phys; /* bit-field */
    struct __attribute__((packed))
    { /* settings for PHY 1M only          */
        uint8_t scan_type;
        uint16_t scan_interval;
        uint16_t scan_window;
    } phy_1m;
} le_set_ext_scan_params_cp;

/* Extended-scan enable CP --------------------------------------------- */
typedef struct __attribute__((packed))
{
    uint8_t enable;
    uint8_t filter_dup;
    uint16_t duration; /* 0 = no limit */
    uint16_t period;   /* 0 = no periodic scan */
} le_set_ext_scan_enable_cp;

/* Build generic HCI request */
static struct hci_request hci_req(uint16_t ocf, int clen, void *status, void *cp)
{
    struct hci_request rq = {0};
    rq.ogf = OGF_LE_CTL;
    rq.ocf = ocf;
    rq.cparam = cp;
    rq.clen = clen;
    rq.rparam = status;
    rq.rlen = 1;
    return rq;
}

/* FAL (Filter Accept List) commands */
#ifndef OCF_LE_CLEAR_FAL
#define OCF_LE_CLEAR_FAL 0x0010
#define OCF_LE_ADD_DEV_FAL 0x0011
#else
#define OCF_LE_CLEAR_FAL 0x002F
#define OCF_LE_ADD_DEV_FAL 0x0030
#endif

/**
 * Clear the Filter Accept List (FAL).
 */
static int fal_clear(int dev)
{
    uint8_t status;
    struct hci_request rq = hci_req(OCF_LE_CLEAR_FAL, 0, &status, NULL);
    if (hci_send_req(dev, &rq, 1000) < 0 || status)
    {
        fprintf(stderr, "LE Clear FAL failed (status 0x%02X)\n", status);
        return -1;
    }
    return 0;
}

/**
 * Add a device to the Filter Accept List (FAL).
 *
 * @param dev        HCI device handle
 * @param addr_str   Address string in format "XX:XX:XX:XX:XX:XX"
 * @param addr_type  Address type (0x00 for public, 0x01 for random)
 * @return           0 on success, -1 on failure
 */
static int fal_add(int dev, const char *addr_str, uint8_t addr_type)
{
    struct
    {
        uint8_t addr_type;
        bdaddr_t addr;
    } __attribute__((packed)) cp;

    if (str2ba(addr_str, &cp.addr) < 0)
    {
        fprintf(stderr, "bad addr %s\n", addr_str);
        return -1;
    }
    cp.addr_type = addr_type;

    uint8_t status;
    struct hci_request rq = hci_req(OCF_LE_ADD_DEV_FAL, sizeof(cp), &status, &cp);
    if (hci_send_req(dev, &rq, 1000) < 0 || status)
    {
        fprintf(stderr, "LE Add Dev FAL failed (status 0x%02X)\n", status);
        return -1;
    }
    return 0;
}

/* ─────────── 4.  MQTT HELPERS        ────────────────────────────── */

/**
 * Initialize the MQTT library and create a new client instance.
 */
static int mqtt_init(void)
{
    mosquitto_lib_init();
    mq = mosquitto_new("borus-publisher", true, NULL);

    if (!mq)
    {
        fprintf(stderr, "mosquitto_new failed\n");
        return -1;
    }

    if (mosquitto_connect_async(mq, BROKER_ADDR, BROKER_PORT, 60))
    {
        fprintf(stderr, "Unable to connect to MQTT broker %s: %d\n", BROKER_ADDR, BROKER_PORT);
        return -1;
    }

    if (mosquitto_loop_start(mq))
    {
        fprintf(stderr, "mosquitto_loop_start failed\n");
        return -1;
    }

    return 0;
}

/**
 * Clean up the MQTT client and library.
 */
static void mqtt_cleanup(void)
{
    if (!mq)
    {
        return;
    }

    mosquitto_loop_stop(mq, true);
    mosquitto_disconnect(mq);
    mosquitto_destroy(mq);
    mosquitto_lib_cleanup();
    mq = NULL;
}

/**
 * Publish a JSON formatted string to the MQTT topic.
 */
static void mqtt_publish_json(const char *js)
{
    if (!mq)
    {
        return;
    }

    mosquitto_publish(mq, NULL, MQTT_TOPIC, (int)strlen(js), js, 0, false);
}

/* ─────────── 5.  TO JSON HELPERS        ────────────────────────────── */

#define JSON_BUF 4096

typedef struct
{                 /* we already declared this in the file */
    int16_t v[6]; /* aX,aY,aZ,gX,gY,gZ ×100              */
    uint32_t ts;  /* sample-relative timestamp            */
} imu_payload_t;

/**
 * Emit JSON formatted data to JSON and publish to MQTT.
 *
 * @param rssi       Received Signal Strength Indicator
 * @param tempC      Temperature in degrees Celsius
 * @param press_hPa  Pressure in hectopascals
 * @param batt_mV    Battery voltage in millivolts
 * @param soc_deg    State of Charge in degrees Celsius
 * @param n          Number of IMU samples
 * @param s          Pointer to an array of imu_payload_t samples
 *
 */
static void emit_json_full(int8_t rssi, int tempC, float press_hPa,
                           int batt_mV, int soc_deg, uint8_t npm_err,
                           uint8_t n, const imu_payload_t *s)
{
    char buf[JSON_BUF];
    char *p = buf;
    int left = JSON_BUF;

    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", tm);

    int w = snprintf(p, left,
                     "{"
                     "\"timestamp\":\"%s\","
                     "\"measurements\":[",
                     timestamp);
    p += w;
    left -= w;

    w = snprintf(p, left,
                 "{\"property\":\"rssi\",\"value\":%d,\"unit\":\"dBm\"},"
                 "{\"property\":\"temperature\",\"value\":%d,\"unit\":\"degC\"},"
                 "{\"property\":\"pressure\",\"value\":%.2f,\"unit\":\"hPa\"},"
                 "{\"property\":\"battery_voltage\",\"value\":%d,\"unit\":\"mV\"},"
                 "{\"property\":\"soc_temperature\",\"value\":%d,\"unit\":\"degC\"},"
                 "{\"property\":\"npm_status\",\"value\":%d,\"unit\":\"NULL\"},",
                 rssi, tempC, press_hPa, batt_mV, soc_deg, npm_err);
    p += w;
    left -= w;

    for (uint8_t i = 0; i < n && left > 0; i++)
    {
        const imu_payload_t *sp = &s[i];
        w = snprintf(p, left,
                     "{\"property\":\"acceleration\","
                     "\"value\":[%.2f,%.2f,%.2f],"
                     "\"unit\":\"m/s^2\","
                     "\"ts\":%u}",
                     sp->v[0] / 100.0f, sp->v[1] / 100.0f, sp->v[2] / 100.0f, sp->ts);
        p += w;
        left -= w;

        w = snprintf(p, left,
                     ",{\"property\":\"gyroscope\","
                     "\"value\":[%.2f,%.2f,%.2f],"
                     "\"unit\":\"rad/s\","
                     "\"ts\":%u}",
                     sp->v[3] / 100.0f, sp->v[4] / 100.0f, sp->v[5] / 100.0f, sp->ts);
        p += w;
        left -= w;
    }
    snprintf(p, left, "]}\n");

    fputs(buf, stdout);
    fflush(stdout);

    mqtt_publish_json(buf);
}

/* ─────────── 6.  EXT-ADVERTISER HELPERS ────────────────────────────── */

/**
 * Set the static advertising address for the extended advertiser.
 *
 * @param dev       HCI device handle
 * @param handle    Advertising handle (0x00 for first set)
 * @param str_addr  Address string in format "XX:XX:XX:XX:XX:XX"
 * @return          0 on success, -1 on failure
 */
static int set_static_adv_addr(int dev, uint8_t handle, const char *str_addr)
{
    struct
    {
        uint8_t handle;
        uint8_t addr[6];
    } __attribute__((packed)) cp;
    uint8_t status;

    cp.handle = handle;
    if (str2ba(str_addr, (bdaddr_t *)cp.addr) < 0)
    {
        fprintf(stderr, "bad addr %s\n", str_addr);
        return -1;
    }

    struct hci_request rq = {
        .ogf = OGF_LE_CTL,
        .ocf = 0x0035,
        .cparam = &cp,
        .clen = sizeof(cp),
        .rparam = &status,
        .rlen = 1};

    if (hci_send_req(dev, &rq, 1000) < 0 || status)
    {
        fprintf(stderr, "SetAdvRandomAddr failed (status 0x%02X)\n", status);
        return -1;
    }

    return 0;
}

/**
 * Set the extended advertising parameters for the advertiser.
 *
 * @param dev  HCI device handle
 * @return     0 on success, -1 on failure
 */
static int set_ext_adv_params(int dev)
{
    le_set_ext_adv_params_cp cp = {0};
    cp.handle = 0x00;
    cp.evt_prop = htobs(0x0010 | 0x0002);     /* legacy PDU, non-scan, non-conn */
    UINT24_TO_ARRAY(0x0050, cp.prim_int_min); /* 100 ms */
    UINT24_TO_ARRAY(0x0052, cp.prim_int_max); /* 150 ms */
    cp.prim_chn_map = 0x07;
    cp.own_addr_type = 0x01;
    cp.adv_tx_power = 0x7F;
    cp.prim_adv_phy = 0x01;
    cp.sec_adv_phy = 0x01;

    uint8_t st;
    struct hci_request rq = hci_req(OCF_LE_SET_EXT_ADV_PARAMS, sizeof(cp), &st, &cp);
    if (hci_send_req(dev, &rq, 1000) < 0 || st)
    {
        fprintf(stderr, "ext adv param fail 0x%02X\n", st);
        return -1;
    }
    return 0;
}

/**
 * Set the extended advertising data with a time counter.
 */
static int set_ext_adv_data_time(int dev, uint16_t time_cs)
{
    le_set_ext_adv_data_cp cp = {0};
    cp.handle = 0x00;
    cp.operation = 0x03; /* complete data */
    cp.frag_pref = 0x00;
    uint8_t *d = cp.data;
    *d++ = 0x05;    // length of the data: Change this if input of the function changes
    *d++ = 0xFF;    // type: Manufacturer Specific Data
    *d++ = 0x59;    // company ID low byte (Nordic Semiconductor)
    *d++ = 0x00;    // company ID high byte
    *d++ = (uint8_t)(time_cs & 0xFF);
    *d++ = (uint8_t)(time_cs >> 8);
    cp.data_len = d - cp.data;

    uint8_t st;
    struct hci_request rq = hci_req(OCF_LE_SET_EXT_ADV_DATA, 4 + cp.data_len, &st, &cp);
    if (hci_send_req(dev, &rq, 1000) < 0 || st)
    {
        fprintf(stderr, "ext adv data fail 0x%02X\n", st);
        return -1;
    }
    return 0;
}

/**
 * Enable or disable the extended advertising.
 *
 * @param dev  HCI device handle
 * @param en   true to enable, false to disable
 * @return     0 on success, -1 on failure
 */
static int set_ext_adv_enable(int dev, bool en)
{
    le_set_ext_adv_enable_cp cp = {0};
    cp.enable = en ? 1 : 0;
    cp.num_sets = 1;
    cp.set[0].handle = 0x00;

    uint8_t st;
    struct hci_request rq = hci_req(OCF_LE_SET_EXT_ADV_ENABLE, sizeof(cp), &st, &cp);
    if (hci_send_req(dev, &rq, 1000) < 0 || st)
    {
        fprintf(stderr, "ext adv %s fail 0x%02X\n", en ? "en" : "dis", st);
        return -1;
    }
    return 0;
}

/* ─────────── 6.  EXT-SCANNER HELPERS ───────────────────────────────── */

/**
 * Set the extended scan parameters for the scanner.
 *
 * @param dev  HCI device handle
 * @return     0 on success, -1 on failure
 */
static int set_ext_scan_params(int dev)
/* passive scan, 1 M PHY, 10 ms window */
{
    le_set_ext_scan_params_cp cp = {0};
    cp.own_addr_type = 0x00;
    cp.scanning_filter_policy = 0x01;       /* 0=accept all, 1=accept only FAL */
    cp.scanning_phys = LE_SCAN_PHY_1M;
    cp.phy_1m.scan_type = 0x00;              /* passive */
    cp.phy_1m.scan_interval = htobs(0x0010); /* 10 ms  */
    cp.phy_1m.scan_window = htobs(0x0010);   /* 10 ms  */

    uint8_t st;
    struct hci_request rq = hci_req(OCF_LE_SET_EXT_SCAN_PARAMS, sizeof(cp), &st, &cp);
    if (hci_send_req(dev, &rq, 1000) < 0 || st)
    {
        fprintf(stderr, "ext scan param fail 0x%02X\n", st);
        return -1;
    }
    return 0;
}

/**
 * Enable or disable the extended scanning.
 *
 * @param dev        HCI device handle
 * @param en         true to enable, false to disable
 * @param filter_dup true to filter duplicate reports, false otherwise
 * @return           0 on success, -1 on failure
 */
static int set_ext_scan_enable(int dev, bool en, bool filter_dup)
{
    le_set_ext_scan_enable_cp cp = {0};
    cp.enable = en ? 1 : 0;
    cp.filter_dup = filter_dup ? 1 : 0; /* 0=disable,1=enable */
    cp.duration = 0;                    /* continuous */
    cp.period = 0;

    uint8_t st;
    struct hci_request rq = hci_req(OCF_LE_SET_EXT_SCAN_ENABLE, sizeof(cp), &st, &cp);
    if (hci_send_req(dev, &rq, 1000) < 0 || st)
    {
        fprintf(stderr, "ext scan %s fail 0x%02X\n", en ? "en" : "dis", st);
        return -1;
    }
    return 0;
}

/* ─────────── 7.  AES-CTR DECRYPT (unchanged) ───────────────────────── */

/**
 * Decrypt a sensor data block using AES-CTR mode.
 *
 * @param key     AES key (16 bytes)
 * @param nonce   Nonce (8 bytes)
 * @param cipher  Ciphertext (sensor data block, 230 bytes)
 * @param plain   Output buffer for plaintext (230 bytes)
 *
 * @return        0 on success, negative error code on failure
 */
static int decrypt_sensor_block_ap(const unsigned char *key,
                                   const uint8_t *nonce,
                                   const uint8_t *cipher,
                                   uint8_t *plain)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, plen = 0, ret = 0;
    unsigned char iv[AES_BLOCK_SIZE] = {0};
    memcpy(iv, nonce, NONCE_LEN);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        ret = -1;
        goto done;
    }
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
    {
        ret = -2;
        goto done;
    }
    if (1 != EVP_DecryptUpdate(ctx, plain, &len, cipher, SENSOR_DATA_PACKET_SIZE))
    {
        ret = -3;
        goto done;
    }
    plen = len;
    if (1 != EVP_DecryptFinal_ex(ctx, plain + len, &len))
    {
        ret = -4;
        goto done;
    }
    plen += len;
    ret = (plen == SENSOR_DATA_PACKET_SIZE) ? 0 : -5;
done:
    if (ret)
        ERR_print_errors_fp(stderr);
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* ─────────── 8.  SIGNALS & TIMERS ───────────────────────────────────── */

static void term_handler(int s)
{
    (void)s;
    shutdown_requested = 1;
}
static void alarm_handler(int s)
{
    (void)s;
    trigger_ap_burst_now = 1;
}

static int schedule_ap_burst(long sec, long usec)
{
    struct itimerval tv = {.it_value = {.tv_sec = sec, .tv_usec = usec}};
    return setitimer(ITIMER_REAL, &tv, NULL);
}

static uint16_t time_to_next_cs(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t now = (uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec;
    uint64_t next = (uint64_t)next_regular_burst_epoch * 1000000ULL;
    if (next <= now)
        return 0;
    uint64_t dcs = (next - now + 9999ULL) / 10000ULL;
    return dcs > 0xFFFF ? 0xFFFF : (uint16_t)dcs;
}

/* ─────────── 8.  PROCESS EXTENDED ADV REPORTS  ─────────────────────── */

#define MAX_ADV_BUF 260 /* 229 + 15 + safety */

typedef struct
{
    bdaddr_t addr;
    uint8_t sid;
    int len;
    uint8_t data[MAX_ADV_BUF];
} adv_acc_t;

/* ------------------------------------------------------------------ */
/*  process_scan_packet() -- reassemble two fragments and debug print */
/* ------------------------------------------------------------------ */
static void process_scan_packet(uint8_t *buf, int len)
{
    /* ---------- static re-assembly state (only one BORUS device) ---- */
    static uint8_t acc_data[260];
    static int acc_len = 0;
    static bdaddr_t acc_addr = {{0}};
    static uint8_t acc_sid = 0xFF;

    if (len < HCI_EVENT_HDR_SIZE + 1 + EVT_LE_META_EVENT_SIZE)
        return;

    evt_le_meta_event *me = (void *)(buf + HCI_EVENT_HDR_SIZE + 1);
    if (me->subevent != EVT_LE_EXTENDED_ADVERTISING_REPORT)
        return;

    uint8_t reports = me->data[0];
    uint8_t *rp = me->data + 1;

    while (reports--)
    {
        /* --- fixed header ------------------------------------------ */
        uint16_t evt_type = le16_to_cpu(*(uint16_t *)rp);
        rp += 2;
        uint8_t addr_type = *rp++;
        bdaddr_t addr;
        memcpy(&addr, rp, 6);
        rp += 6;
        uint8_t prim_phy = *rp++, sec_phy = *rp++, sid = *rp++;
        int8_t tx_pwr = *rp++, rssi = *rp++;
        rp += 2 /* periodic int */ + 1 + 6; /* dir addr */
        uint8_t adv_len = *rp++;

        uint8_t *adv = rp;
        rp += adv_len;

        /* only care about our BORUS MAC */
        char addr_str[18];
        ba2str(&addr, addr_str);
        if (strcmp(addr_str, target_mac))
            continue;

        /* ---------- (re)start accumulator if new addr/SID ---------- */
        if (bacmp(&addr, &acc_addr) || sid != acc_sid)
        {
            acc_addr = addr;
            acc_sid = sid;
            acc_len = 0;
        }

        if (acc_len + adv_len > sizeof(acc_data)) /* shouldn't happen */
            acc_len = 0;

        memcpy(acc_data + acc_len, adv, adv_len);
        acc_len += adv_len;

        /* need at least 2 bytes to read first AD header */
        if (acc_len < 2)
            continue;

        uint8_t field_len = acc_data[0];
        uint8_t field_type = acc_data[1];

        /* wait until the whole Manufacturer block (len+1 bytes) is present */
        if (field_type != 0xFF || acc_len < field_len + 1)
            continue;

        /*  Now parse manufacturer payload --------------------------- */
        uint8_t *pay_start = &acc_data[2]; // This is custom type | nonce | sensor data
        uint8_t pay_len = field_len - 1;   // This is the length of custom type | nonce | sensor data

        uint8_t ptype = pay_start[0];     // This is custom type
        uint8_t *payload = &pay_start[1]; // This is nonce | sensor data
        uint16_t plen = pay_len - 1;      // This is the length of nonce | sensor data

        uint8_t *nonce = payload;
        uint16_t cid = (nonce[0]) | (nonce[1] << 8);
        if (cid != BORUS_COMPANY_ID && ptype == SENSOR_ADV_PAYLOAD_TYPE)
        {
            printf("  CID mismatch (0x%04X) skipping\n", cid);
            acc_len = 0;
            continue;
        }

        // printf("  ptype=%u  plen=%u\n", ptype, plen);

        if (ptype == SENSOR_ADV_PAYLOAD_TYPE &&
            plen == SENSOR_PAYLOAD_DATA_LEN)
        {

            uint8_t plain[SENSOR_DATA_PACKET_SIZE];
            if (decrypt_sensor_block_ap(aes_key, payload,
                                        payload + NONCE_LEN,
                                        plain) == 0)
            {
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
                int batt = plain[off++] * 20;

                // SoC temperature
                int8_t soc_temp = plain[off++];

                // NPM1100 err status
                uint8_t npm_err = plain[off++];

                // Number of IMU batch
                uint8_t number_of_batch = plain[off++];

                // IMU Batch
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

                emit_json_full(rssi, tempC, press, batt, soc_temp, npm_err,
                               number_of_batch, samples );
            }
            else
            {
                printf("  Decrypt FAILED\n");
            }
        }
        else if (ptype == AWAY_ADV_PAYLOAD_TYPE && plen == SYNC_REQ_PAYLOAD_DATA_LEN)
        {
            uint16_t delay_s = payload[0] | (payload[1] << 8);
            // printf("SYNC-REQ wearable scans in %u s\n", delay_s);

            long trig_us = (long)delay_s * 1000000L - (long)RPI_SAFETY_MARGIN_MS * 1000L;
            if (trig_us < 50000)
            {
                trig_us = 50000;
            }

            schedule_ap_burst(trig_us / 1000000L, trig_us % 1000000L);
            next_regular_burst_epoch = time(NULL) + (trig_us / 1000000L);
        }

        /*  reset accumulator for next advertising event               */
        acc_len = 0;
    }
}

/* ─────────── 10.  MAIN LOOP ─────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    srand(time(NULL));
    signal(SIGINT, term_handler);
    signal(SIGTERM, term_handler);
    signal(SIGALRM, alarm_handler);

    // Choose which HCI device to open
    int wanted_dev = -1;

    if (argc > 1)
    {
        char *endp;
        wanted_dev = strtol(argv[1], &endp, 10);
        if (*endp || wanted_dev < 0)
        {
            fprintf(stderr,
                    "Usage: %s [hci_index]\n"
                    "   (omit hci_index to auto-probe)\n",
                    argv[0]);
            return 1;
        }
    }

    if (wanted_dev >= 0)
    {
        device = hci_open_dev(wanted_dev);
    }
    else
    {
        device = hci_open_dev(1);
        if (device < 0)
        {
            device = hci_open_dev(0);
        }
    }

    if (device < 0)
    {
        perror("hci_open_dev");
        return 1;
    }
    int fl = fcntl(device, F_GETFL, 0);
    fcntl(device, F_SETFL, fl | O_NONBLOCK);

    if (mqtt_init() < 0)
    {
        fprintf(stderr, "Failed to initialise MQTT - continuing without publish\n");
    }

    // Set random address
    if (set_static_adv_addr(device, 0x00, random_ble_addr) < 0)
    {
        perror("Set random static addr");
        goto exit;
    }

    if (set_ext_adv_params(device) < 0)
        goto exit;
    if (fal_clear(device) < 0)
        goto exit;
    if (fal_add(device, target_mac, 0x01) < 0)
        goto exit;
    if (set_ext_scan_params(device) < 0)
        goto exit;

    struct hci_filter flt;
    hci_filter_clear(&flt);
    hci_filter_set_ptype(HCI_EVENT_PKT, &flt);
    hci_filter_set_event(EVT_LE_META_EVENT, &flt);
    setsockopt(device, SOL_HCI, HCI_FILTER, &flt, sizeof(flt));

    bool scanning = false, advertising = false;

    while (!shutdown_requested)
    {
        if (trigger_ap_burst_now)
        {
            trigger_ap_burst_now = 0;

            int tcs = time_to_next_cs();
            if (scanning)
            {
                set_ext_scan_enable(device, false, false);
                scanning = false;
                usleep(50000);
            }
            set_ext_adv_data_time(device, (uint16_t)tcs);
            set_ext_adv_enable(device, true);
            advertising = true;
            usleep(ADV_BURST_DURATION_MS * 1000);
            set_ext_adv_enable(device, false);
            advertising = false;

            usleep(50000);
        }

        if (!scanning && !advertising)
        {
            if (set_ext_scan_enable(device, true, false) == 0)
                scanning = true;
            else
            {
                perror("scan enable");
                sleep(1);
            }
        }

        if (scanning)
        {
            uint8_t buf[HCI_MAX_EVENT_SIZE];
            while (scanning)
            {
                int n = read(device, buf, sizeof(buf));
                if (n < 0)
                {
                    if (errno == EAGAIN)
                        break;
                    perror("read");
                    set_ext_scan_enable(device, false, false);
                    scanning = false;
                    break;
                }
                else if (n > 0)
                    process_scan_packet(buf, n);
                else
                    break;
            }
        }
        usleep(1000);
    }

exit:
    schedule_ap_burst(0, 0);
    set_ext_scan_enable(device, false, false);
    set_ext_adv_enable(device, false);
    if (device >= 0)
    {
        hci_close_dev(device);
    }
    mqtt_cleanup();
    return 0;
}
