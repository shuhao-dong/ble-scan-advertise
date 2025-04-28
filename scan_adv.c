// Copyright (c) 2021 David G. Young
// Copyright (c) 2015 Damian Kołakowski. All rights reserved.

// Compile with:
// cc scan_adv.c -o scan_adv -lbluetooth -lssl -lcrypto

// Modified by: Shuhao Dong
// Implements:
// - Periodic Advertising (AP Heartbeat) with Jitter
// - Includes time until next AP burst in ADV packet for negotiation
// - Scanning for BORUS device advertisements
// - Decryption of BORUS sensor data payload

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <time.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>

// --- Configuration ---
// Target BORUS device MAC to listen for (MUST MATCH YOUR DEVICE)
const char target_mac[] = "EE:93:96:3C:66:B5"; // REPLACE WITH YOUR BORUS DEVICE ADDRESS

// Periodic Advertising (AP Heartbeat) Configuration
#define BASE_ADV_INTERVAL_S 60  // Base interval for AP advertising bursts (seconds)
#define JITTER_S 15             // Max random jitter to add (0-15 seconds)
#define ADV_BURST_DURATION_MS 500 // How long AP advertises each time (milliseconds)
// Company ID used in AP's Manufacturer Data (Example: 0xACDC)
#define AP_COMPANY_ID_LSB 0xDC
#define AP_COMPANY_ID_MSB 0xAC

// Decryption Configuration (from BORUS device)
#define SENSOR_DATA_PACKET_SIZE 20 // Plaintext size from BORUS
#define NONCE_LEN 8                // Nonce size from BORUS
#define ENC_ADV_PAYLOAD_LEN (NONCE_LEN + SENSOR_DATA_PACKET_SIZE) // = 28
#define BORUS_COMPANY_ID 0x0059 // Expected Company ID in BORUS packet nonce

// !!! IMPORTANT: Use the EXACT SAME KEY as on the BORUS device !!!
const unsigned char aes_key[16] = {
    0x9F, 0x7B, 0x25, 0xA0, 0x68, 0x52, 0x33, 0x1C,
    0x10, 0x42, 0x5E, 0x71, 0x99, 0x84, 0xC7, 0xDD
};

// BORUS Device Data Format Constants (from prepare_packet)
#define TEMPERATURE_LOW_LIMIT 30
#define PRESSURE_BASE_HPA_X10 8500

// Global HCI device handle
int device = -1;

// --- HCI Helper Function ---
/**
 * @brief Creates a standard HCI request structure.
 */
struct hci_request ble_hci_request(uint16_t ocf, int clen, void *status, void *cparam)
{
    struct hci_request rq;
    memset(&rq, 0, sizeof(rq));
    rq.ogf = OGF_LE_CTL;
    rq.ocf = ocf;
    rq.cparam = cparam;
    rq.clen = clen;
    rq.rparam = status;
    rq.rlen = 1; // Expect status byte in return
    return rq;
}

// --- Bluetooth Configuration Functions ---

/**
 * @brief Sets LE Advertising Parameters for AP's heartbeat advertisements.
 */
int set_advertising_parameters(int dev)
{
    le_set_advertising_parameters_cp adv_params_cp;
    memset(&adv_params_cp, 0, sizeof(adv_params_cp));
    adv_params_cp.min_interval = htobs(0x00A0); // 100ms
    adv_params_cp.max_interval = htobs(0x00F0); // 150ms (Wider range might help visibility)
    adv_params_cp.advtype = 0x03;           // Non-connectable undirected advertising (ADV_NONCONN_IND)
    adv_params_cp.own_bdaddr_type = 0x00;   // Use Public Address (or 0x01 if random address is set)
    adv_params_cp.chan_map = 0x07;          // All channels
    adv_params_cp.filter = 0x00;            // No filter

    uint8_t status;
    struct hci_request adv_params_rq = ble_hci_request(OCF_LE_SET_ADVERTISING_PARAMETERS,
                                                       LE_SET_ADVERTISING_PARAMETERS_CP_SIZE,
                                                       &status, &adv_params_cp);
    int ret = hci_send_req(dev, &adv_params_rq, 1000);
    if (ret < 0 || status != 0) {
        perror("AP: Failed to set advertising parameters");
        fprintf(stderr, "AP: HCI Status: 0x%02X\n", status); return -1;
    }
    printf("AP: Advertising parameters set.\n"); return 0;
}

/**
 * @brief Sets LE Advertising Data for AP's heartbeat, including time until next burst.
 */
int set_advertising_data(int dev, uint16_t time_to_next_s)
{
    le_set_advertising_data_cp adv_data_cp;
    memset(&adv_data_cp, 0, sizeof(adv_data_cp));
    uint8_t index = 0;

    // --- Manufacturer Specific Data AD Structure ---
    // Length: 1 byte Type + 2 bytes Company ID + 2 bytes Time Data = 5 bytes total field length
    adv_data_cp.data[index++] = 0x05; // Field Length
    adv_data_cp.data[index++] = 0xFF; // Type: Manufacturer Specific Data
    adv_data_cp.data[index++] = 0x59;
    adv_data_cp.data[index++] = 0x00;
    // Encode time as Little Endian uint16_t
    adv_data_cp.data[index++] = (uint8_t)(time_to_next_s & 0xFF);        // Time LSB
    adv_data_cp.data[index++] = (uint8_t)((time_to_next_s >> 8) & 0xFF); // Time MSB

    adv_data_cp.length = index; // Total length of all AD structures included

    uint8_t status;
    struct hci_request adv_data_rq = ble_hci_request(OCF_LE_SET_ADVERTISING_DATA,
                                                     1 + adv_data_cp.length, // clen = 1 byte length field + data
                                                     &status, &adv_data_cp);
    int ret = hci_send_req(dev, &adv_data_rq, 1000);
    if (ret < 0 || status != 0) {
        perror("AP: Failed to set advertising data with time");
        fprintf(stderr, "AP: HCI Status: 0x%02X\n", status); return -1;
    }
    // printf("AP: Advertising data set (Time until next: %u s).\n", time_to_next_s);
    return 0;
}

/**
 * @brief Enable or disable AP advertising.
 */
int set_advertise_enable(int dev, bool enable)
{
    le_set_advertise_enable_cp advertise_cp;
    memset(&advertise_cp, 0, sizeof(advertise_cp));
    advertise_cp.enable = enable ? 0x01 : 0x00;

    uint8_t status;
    struct hci_request enable_adv_rq = ble_hci_request(OCF_LE_SET_ADVERTISE_ENABLE,
                                                       LE_SET_ADVERTISE_ENABLE_CP_SIZE,
                                                       &status, &advertise_cp);
    int ret = hci_send_req(dev, &enable_adv_rq, 1000);
    if (ret < 0 || status != 0) {
        fprintf(stderr, "AP: Failed to %s advertising, Status: 0x%02X\n", enable ? "enable" : "disable", status);
        perror("AP: set_advertise_enable"); return -1;
    }
    return 0;
}

/**
 * @brief Sets LE Scan Parameters for listening to BORUS.
 */
int set_scan_parameters(int dev) {
    le_set_scan_parameters_cp scan_params_cp;
    memset(&scan_params_cp, 0, sizeof(scan_params_cp));
    // Use Passive Scan as sensor data is in main ADV packet
    scan_params_cp.type = 0x00;
    // Use aggressive scanning parameters to catch fast BORUS advertisements
    scan_params_cp.interval = htobs(0x0010); // 10ms interval
    scan_params_cp.window = htobs(0x0010);   // 10ms window (100% duty cycle)
    scan_params_cp.own_bdaddr_type = 0x00;   // Public Device Address
    scan_params_cp.filter = 0x00;            // Accept all advertisements

    uint8_t status;
    struct hci_request scan_params_rq = ble_hci_request(OCF_LE_SET_SCAN_PARAMETERS,
                                                        LE_SET_SCAN_PARAMETERS_CP_SIZE,
                                                        &status, &scan_params_cp);
    int ret = hci_send_req(dev, &scan_params_rq, 1000);
    if (ret < 0 || status != 0) {
        perror("AP: Failed to set scan parameters (Passive)");
        fprintf(stderr, "AP: HCI Status: 0x%02X\n", status); return -1;
    }
     printf("AP: Scan parameters set (Passive Scan).\n"); return 0;
}

/**
 * @brief Enable or disable LE scanning.
 */
int set_scan_enable(int dev, bool enable, bool filter_duplicates) {
    le_set_scan_enable_cp scan_cp;
    memset(&scan_cp, 0, sizeof(scan_cp));
    scan_cp.enable = enable ? 0x01 : 0x00;
    scan_cp.filter_dup = filter_duplicates ? 0x01 : 0x00; // Disable filtering for higher rate

    uint8_t status;
    struct hci_request enable_scan_rq = ble_hci_request(OCF_LE_SET_SCAN_ENABLE,
                                                        LE_SET_SCAN_ENABLE_CP_SIZE,
                                                        &status, &scan_cp);
    int ret = hci_send_req(dev, &enable_scan_rq, 1000);
    if (ret < 0 || status != 0) {
        fprintf(stderr, "AP: Failed to %s scan, Status: 0x%02X\n", enable ? "enable" : "disable", status);
        perror("AP: set_scan_enable"); return -1;
    }
    return 0;
}

// --- Decryption Function ---
/**
 * @brief Decrypts sensor data using AES-128-CTR.
 * @return 0 on success, negative on failure.
 */
int decrypt_sensor_block_ap(const unsigned char *key, const uint8_t *nonce,
                            const uint8_t *ciphertext, uint8_t *plaintext)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, plaintext_len = 0, ret = 0;
    unsigned char iv[AES_BLOCK_SIZE]; // 16 bytes for AES

    memset(iv, 0, AES_BLOCK_SIZE);
    memcpy(iv, nonce, NONCE_LEN); // Copy 8-byte nonce to start of IV

    ctx = EVP_CIPHER_CTX_new();
    if(!ctx) { ret = -1; goto cleanup_decrypt; }

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv)) {
        ret = -2; goto cleanup_decrypt;
    }
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, SENSOR_DATA_PACKET_SIZE)) {
        ret = -3; goto cleanup_decrypt;
    }
    plaintext_len = len;
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        ret = -4; goto cleanup_decrypt;
    }
    plaintext_len += len;

    if (plaintext_len != SENSOR_DATA_PACKET_SIZE) { ret = -5; } // Length mismatch
    else { ret = 0; } // Success

cleanup_decrypt:
    if (ret != 0) { fprintf(stderr, "AP: Decryption Error Code %d\n", ret); ERR_print_errors_fp(stderr); }
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

// --- Packet Processing Function ---
/**
 * @brief Process received HCI LE Meta Events (Advertising Reports).
 */
void process_scan_packet(uint8_t *buf, int len) {
    if (len < HCI_EVENT_HDR_SIZE + 1 + EVT_LE_META_EVENT_SIZE + 1) return;

    evt_le_meta_event *meta_event = (evt_le_meta_event *)(buf + HCI_EVENT_HDR_SIZE + 1);
    if (meta_event->subevent != EVT_LE_ADVERTISING_REPORT) return;

    uint8_t reports_count = meta_event->data[0];
    void *offset = meta_event->data + 1;

    while (reports_count-- && (offset < (void*)buf + len)) {
        le_advertising_info *info = (le_advertising_info *)offset;
        if ((void*)info + sizeof(le_advertising_info) > (void*)buf + len ||
            (void*)info->data + info->length > (void*)buf + len) {
             fprintf(stderr, "AP: Malformed report data\n"); break;
        }

        char addr[18];
        ba2str(&(info->bdaddr), addr);

        if (strcmp(addr, target_mac) == 0) { // Check if it's our BORUS device
            time_t now = time(NULL);
            char timestamp_str[20];
            strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S", localtime(&now));

            const char *packet_type_str = "Unknown";
            bool is_primary_adv = false;
            // Identify packet type (ADV_IND=0x00, ADV_SCAN_IND=0x02, ADV_NONCONN_IND=0x03)
            if (info->evt_type == 0x00 || info->evt_type == 0x02 || info->evt_type == 0x03) {
                 is_primary_adv = true;
                 packet_type_str = (info->evt_type == 0x00) ? "ADV_IND" : ((info->evt_type == 0x02) ? "ADV_SCAN_IND" : "ADV_NONCONN_IND");
            } else if (info->evt_type == 0x04) {
                 packet_type_str = "SCAN_RSP";
            }

            // Only process primary ADV packets for sensor data now
            if (is_primary_adv) {
                 printf("%s AP: Received %s from BORUS %s RSSI: %d\n", timestamp_str, packet_type_str, addr, (int8_t)info->data[info->length]);

                uint8_t *adv_data = info->data;
                int adv_len = info->length;
                int current_pos = 0;
                bool found_mfr_data = false;

                // Parse AD Structures
                while (current_pos < adv_len) {
                    uint8_t field_len = adv_data[current_pos];
                    if (field_len == 0 || (current_pos + 1 + field_len) > adv_len) break;
                    uint8_t field_type = adv_data[current_pos + 1];
                    uint8_t *field_payload = &adv_data[current_pos + 2];
                    uint8_t payload_len = field_len - 1;

                    if (field_type == 0xFF) { // Manufacturer Specific Data
                        if (payload_len == ENC_ADV_PAYLOAD_LEN) {
                            // Optional: Check Company ID matches BORUS's ID (0x0059)
                            // uint16_t company_id = field_payload[0] | (field_payload[1] << 8); // Assuming LE nonce format
                            // if (company_id == BORUS_COMPANY_ID) { ... }

                            found_mfr_data = true;
                            uint8_t *nonce = field_payload;
                            uint8_t *ciphertext = field_payload + NONCE_LEN;
                            uint8_t plaintext[SENSOR_DATA_PACKET_SIZE];

                            if (decrypt_sensor_block_ap(aes_key, nonce, ciphertext, plaintext) == 0) {
                                // --- Parse Plaintext ---
                                int pt_offset = 0;
                                uint8_t encoded_temp = plaintext[pt_offset++];
                                int temp_c = (int)encoded_temp - TEMPERATURE_LOW_LIMIT;

                                uint16_t pressure_offset = plaintext[pt_offset] | (plaintext[pt_offset+1] << 8); pt_offset += 2;
                                uint16_t pressure_x10hpa = pressure_offset + PRESSURE_BASE_HPA_X10;

                                int16_t imu[6]; memcpy(imu, &plaintext[pt_offset], sizeof(imu)); pt_offset += sizeof(imu);

                                uint32_t ts = plaintext[pt_offset] | (plaintext[pt_offset+1] << 8) | (plaintext[pt_offset+2] << 16) | (plaintext[pt_offset+3] << 24); pt_offset += 4;

                                uint8_t batt_pct = plaintext[pt_offset++];

                                printf("AP: DECRYPTED -> Temp:%dC Pres:%.1fhPa Batt:%u%% TS:%u IMU:[%d,%d,%d,%d,%d,%d]\n",
                                       temp_c, (float)pressure_x10hpa / 10.0, batt_pct, ts,
                                       imu[0], imu[1], imu[2], imu[3], imu[4], imu[5]);
                                fflush(stdout);
                            } else { /* Decryption failed msg already printed */ }
                        } else {
                             fprintf(stderr, "AP: Mfr data len mismatch in %s (Exp %d, Got %u)\n", packet_type_str, ENC_ADV_PAYLOAD_LEN, payload_len);
                        }
                        break; // Found Mfr data
                    }
                    current_pos += (1 + field_len);
                } // end while(parsing AD)
                if (!found_mfr_data) printf("AP: Mfr data (0xFF) not found or wrong size in %s.\n", packet_type_str);
            } else {
                // Log other packet types if needed, but don't process for sensor data
                // printf("%s AP: Received %s from BORUS %s RSSI: %d (Ignoring data)\n", timestamp_str, packet_type_str, addr, (int8_t)info->data[info->length]);
            }
            break; // Found BORUS, stop processing reports in this event
        }
        offset = info->data + info->length + 1; // Move to next report
    }
}

// --- Main Function ---
int main()
{
    int ret;
    srand(time(NULL));

    // --- HCI Device Initialization ---
    printf("AP: Opening HCI device...\n");
    device = hci_open_dev(1); if (device < 0) device = hci_open_dev(0);
    if (device < 0) { perror("AP: Failed to open any HCI device."); return 1; }
    printf("AP: Using device %d\n", device);

    int flags = fcntl(device, F_GETFL, 0);
    if (flags == -1 || fcntl(device, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("AP: Failed to set socket non-blocking"); hci_close_dev(device); return 1;
    }
    printf("AP: HCI device opened and set to non-blocking.\n");

    // --- Initial BLE Configuration ---
    printf("AP: Configuring initial BLE parameters...\n");
    if (set_advertising_parameters(device) < 0) goto ap_cleanup; // For AP's own ADV
    // Set initial advertising data (time value will be updated before first burst)
    if (set_advertising_data(device, 0) < 0) goto ap_cleanup;
    if (set_scan_parameters(device) < 0) goto ap_cleanup; // For scanning BORUS

    // Set HCI event filter for LE Meta Events
    struct hci_filter nf;
    hci_filter_clear(&nf);
    hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
    hci_filter_set_event(EVT_LE_META_EVENT, &nf);
    if (setsockopt(device, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0) {
        perror("AP: Could not set HCI filter"); goto ap_cleanup;
    }
    printf("AP: HCI filter set.\n");

    // --- Main Loop Variables ---
    time_t last_adv_time = 0; // Ensures first advertisement happens quickly
    int next_adv_interval = BASE_ADV_INTERVAL_S + (rand() % (JITTER_S + 1)); // Initial interval
	set_advertising_data(device, next_adv_interval);
    bool is_scanning = false;
    bool is_advertising = false;

    printf("AP: Starting main loop (Passive Scan + Periodic Advertise w/ Time Negotiation)...\n");
    printf("AP: Initial next advertising burst in %d seconds.\n", next_adv_interval);

    // --- Main Loop ---
    while (1) {
        time_t now = time(NULL);

        // --- Periodic Advertising Burst Logic ---
        if (!is_advertising && (now >= last_adv_time + next_adv_interval)) {

            int interval_for_following_burst = BASE_ADV_INTERVAL_S + (rand() % (JITTER_S + 1));
            uint16_t time_to_next_burst_s = (uint16_t)interval_for_following_burst;

            printf("AP: [%s] Triggering advertising burst. Advertising time until next burst: %u s\n", ctime(&now), time_to_next_burst_s);

            if (is_scanning) { // Stop scan before advertising
                // Use filter_duplicates=false when stopping/starting scan
                if (set_scan_enable(device, false, false) == 0) { is_scanning = false; usleep(20000); }
                else { fprintf(stderr, "AP: Warn - Failed to disable scan\n"); }
            }

            if (set_advertising_data(device, time_to_next_burst_s) == 0) { // Set data *first*
                if (set_advertise_enable(device, true) == 0) { // Start burst
                    is_advertising = true; usleep(ADV_BURST_DURATION_MS * 1000);
                    set_advertise_enable(device, false); // Stop burst
                    is_advertising = false;
                } else { is_advertising = false; /* Log error */ }
            } else { fprintf(stderr, "AP: Error - Failed set ADV data, skipping burst\n");}


            last_adv_time = time(NULL);
            next_adv_interval = interval_for_following_burst;
            printf("AP: Next advertising burst scheduled in %d seconds.\n", next_adv_interval);
        }

        // --- Continuous Scanning Logic (if not advertising) ---
        if (!is_scanning && !is_advertising) {
             if (set_scan_enable(device, true, false) == 0) { // Start scan, NO duplicate filtering
                is_scanning = true;
             } else { fprintf(stderr, "AP: Error: Failed scan enable! Retrying.\n"); sleep(5); continue; }
        }

        // Process packets if scanning
        if (is_scanning) {
            uint8_t buf[HCI_MAX_EVENT_SIZE];
            // Inner loop to read all available packets quickly
            while (is_scanning) { // Check state again in case adv burst interrupted
                int len = read(device, buf, sizeof(buf));
                if (len < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break; // No more data now
                    else { perror("AP: HCI read error"); set_scan_enable(device, false, false); is_scanning = false; sleep(1); break; }
                } else if (len > 0) {
                    process_scan_packet(buf, len); // Process received packet
                } else { break; } // read() returned 0
            }
        }

        // Yield CPU slightly, especially if read() loop was short (no data)
        usleep(1000); // 1ms

    } // End while(1)

ap_cleanup:
    printf("AP: Cleaning up and closing HCI device.\n");
    if (device >= 0) {
        set_scan_enable(device, false, false);
        set_advertise_enable(device, false);
        hci_close_dev(device);
    }
    return 1;
}