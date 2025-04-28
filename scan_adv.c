// Copyright (c) 2021 David G. Young
// Copyright (c) 2015 Damian Kołakowski. All rights reserved.

// cc scan_adv.c -lbluetooth -lssh -lcrypto -o scan_adv
// Modified by: Shuhao Dong 

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
#include <bits/types/sigset_t.h>
#include <bits/sigaction.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>

// --- Configuration ---
const char target_mac[] = "EE:93:96:3C:66:B5";	// BORUS MAC address

// Periodic Advertising Configuration 
#define BASE_ADV_INTERVAL_S	60
#define JITTER_S	15
#define ADV_BURST_DURATION_MS	500
#define AP_ADV_DATA_VALUE	0xAD

// Decryption Configuration
#define SENSOR_DATA_PACKET_SIZE	20
#define NONCE_LEN	8
#define ENC_ADV_PAYLOAD_LEN	(SENSOR_DATA_PACKET_SIZE + NONCE_LEN)
#define EXPECTED_COMPANY_ID	0X0059	

// AES key
const unsigned char aes_key[16] = {
	0x9F, 0x7B, 0x25, 0xA0, 0x68, 0x52, 0x33, 0x1C,
	0x10, 0x42, 0x5E, 0x71, 0x99, 0x84, 0xC7, 0xDD
}; 

// Data Format Constants
#define TEMPERATURE_LOW_LIMIT	30
#define PRESSURE_BASE_HPA_X10	8500

int device;

/**
 * @brief Creates a standard HCI request structure
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
	rq.rlen = 1;
	return rq;
}

/**
 * @brief Sets LE Advertising Parameters
 */
int set_advertising_parameters(int device)
{
    le_set_advertising_parameters_cp adv_params_cp;
    memset(&adv_params_cp, 0, sizeof(adv_params_cp));
    adv_params_cp.min_interval = htobs(0x00A0);     // 100ms interval for AP heartbeat
    adv_params_cp.max_interval = htobs(0x00B0);     // ~110ms interval 
    adv_params_cp.advtype = 0x03;                   // Non-connectable undirected advertising (ADV_NONCONN_IND)
    adv_params_cp.own_bdaddr_type = 0x00;           // Public device address
    adv_params_cp.chan_map = 0x07;                  // All channels
    adv_params_cp.filter = 0x00;                    // Allow scan from any device 

    uint8_t status;
    struct hci_request adv_params_rq = ble_hci_request(
					OCF_LE_SET_ADVERTISING_PARAMETERS, 
                    LE_SET_ADVERTISING_PARAMETERS_CP_SIZE, 
                    &status, 
                    &adv_params_cp);
    int ret = hci_send_req(device, &adv_params_rq, 1000);
    if (ret < 0 || status != 0){
        perror("Failed to set advertising parameters"); 
		return -1;
    }
	printf("AP: Advertising parameters set.\n");
	return 0; 
}

/**
 * @brief Sets LE Advertising Data
 */
int set_advertising_data(int device, uint8_t my_value)
{
    le_set_advertising_data_cp adv_data_cp;
    memset(&adv_data_cp, 0, sizeof(adv_data_cp));

    uint8_t index = 0;

	// --- Manufacturer Specific Data AD Structure --- 
    adv_data_cp.data[index++] = 4;      // Length of this AD structure
    adv_data_cp.data[index++] = 0xFF;   // Manufacturer Specific Data
    adv_data_cp.data[index++] = my_value;

    // Set the total length of advertising data
    adv_data_cp.length = index;

    uint8_t status;
    struct hci_request adv_data_rq = ble_hci_request(OCF_LE_SET_ADVERTISING_DATA, 
									adv_data_cp.length+1, 
									&status, 
									&adv_data_cp);
    int ret = hci_send_req(device, &adv_data_rq, 1000);
    if (ret < 0 || status != 0){
        perror("Failed to set advertising data"); 
		return -1;
    }
	printf("AP: Advertising data set (Heartbeat Value: 0x%02X).\n", my_value);
	return 0; 
}

/**
 * @brief Enable or disable advertising
 * 
 * @param enable_adv Set 1 to enable, 0 to disable
 * @param device BLE device
 */
int set_advertise_enable(int device, uint8_t enable_adv)
{
    le_set_advertise_enable_cp advertise_cp;
    memset(&advertise_cp, 0, sizeof(advertise_cp));
    advertise_cp.enable = enable_adv ? 0x01: 0x00; // Enable advertising

    uint8_t status;
    struct hci_request enable_adv_rq = ble_hci_request(OCF_LE_SET_ADVERTISE_ENABLE, 
                    LE_SET_ADVERTISE_ENABLE_CP_SIZE,
                    &status,
                    &advertise_cp); 
    int ret = hci_send_req(device, &enable_adv_rq, 1000);
    if (ret < 0 || status != 0){
        perror("Failed to enable advertising"); 
		return -1;
    }
    printf("Advertising ...\n");
	return 0; 
}

int set_scan_parameters(int dev)
{
	le_set_scan_parameters_cp scan_params_cp;
	memset(&scan_params_cp, 0, sizeof(scan_params_cp));
	scan_params_cp.type 			= 0x00;
	scan_params_cp.interval 		= htobs(0x0030);
	scan_params_cp.window 			= htobs(0x0030);
	scan_params_cp.own_bdaddr_type 	= 0x00; // Public Device Address (default).
	scan_params_cp.filter 			= 0x00; // Accept all.

	uint8_t status;
	struct hci_request scan_params_rq = ble_hci_request(OCF_LE_SET_SCAN_PARAMETERS, 
						LE_SET_SCAN_PARAMETERS_CP_SIZE, 
						&status, 
						&scan_params_cp);
	int ret = hci_send_req(device, &scan_params_rq, 1000);
	if (ret < 0 || status != 0) {
		perror("Failed to set scan parameters data.");
		return -1;
	}
	printf("AP: Scan parameters set.\n");
	return 0; 
}

int set_scan_enable(int device, bool enable, bool filter_duplicates)
{
    // Enable scanning
    le_set_scan_enable_cp scan_cp;
	memset(&scan_cp, 0, sizeof(scan_cp));
	scan_cp.enable 		= enable ? 0x01 : 0x00;	// Enable flag.
	scan_cp.filter_dup 	= filter_duplicates? 0x01 : 0x00; // Filtering disabled.

	uint8_t status;
	struct hci_request enable_adv_rq = ble_hci_request(OCF_LE_SET_SCAN_ENABLE, 
						LE_SET_SCAN_ENABLE_CP_SIZE, 
						&status, 
						&scan_cp);

	int ret = hci_send_req(device, &enable_adv_rq, 1000);
	if (ret < 0 || status != 0) {
		perror("Failed to enable scan.");
		return -1;
	}
	return 0; 
}

int decrypt_sensor_block_ap(const unsigned char *key, const uint8_t *nonce, const uint8_t *ciphertext, uint8_t *plaintext)
{
	EVP_CIPHER_CTX *ctx = NULL;
	int len = 0, plaintext_len = 0, ret = 0;

	unsigned char iv[AES_BLOCK_SIZE];
	memset(iv, 0, AES_BLOCK_SIZE);
	memcpy(iv, nonce, NONCE_LEN); 

	ctx = EVP_CIPHER_CTX_new();
	if(!ctx)
	{
		ret = -1;
		goto cleanup_decrypt;
	}

	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
	{
		ret = -2;
		goto cleanup_decrypt;
	}

	if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, SENSOR_DATA_PACKET_SIZE))
	{
		ret = -3;
		goto cleanup_decrypt;
	}
	plaintext_len = len;

	if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
	{
		ret = -4;
		goto cleanup_decrypt;
	}
	plaintext_len += len;

	if (plaintext_len != SENSOR_DATA_PACKET_SIZE)
	{
		ret = -5;
	}
	else
	{
		ret = 0; 
	}

cleanup_decrypt:
	if (ret != 0)
	{
		fprintf(stderr, "AP: Decryption Error Code %d\n", ret);
	}
	if (ctx)
	{
		EVP_CIPHER_CTX_free(ctx);
	}
	return ret;
}

/**
 * @brief Process a received LE Advertising or Scan Response packet.
 *        Now expects sensor data in primary ADV packet (e.g., ADV_IND).
 * @param buf Raw buffer containing the HCI event packet.
 * @param len Length of the buffer.
 */
void process_scan_packet(uint8_t *buf, int len) {
    // ... (Basic length checks remain the same) ...

    evt_le_meta_event *meta_event = (evt_le_meta_event *)(buf + HCI_EVENT_HDR_SIZE + 1);

    if (meta_event->subevent != EVT_LE_ADVERTISING_REPORT) return;

    uint8_t reports_count = meta_event->data[0];
    void *offset = meta_event->data + 1;

    while (reports_count-- && (offset < (void*)buf + len)) {
        le_advertising_info *info = (le_advertising_info *)offset;
        // ... (Validity checks for info struct remain the same) ...

        char addr[18];
        ba2str(&(info->bdaddr), addr);

        // --- Check if it's our target BORUS device ---
        if (strcmp(addr, target_mac) == 0) {
            time_t now = time(NULL);
            char timestamp_str[20];
            strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S", localtime(&now));

            // --- Determine Packet Type ---
            const char *packet_type_str = "Unknown";
            bool is_primary_adv = false;
            switch(info->evt_type) {
                case 0x00: packet_type_str = "ADV_IND"; is_primary_adv = true; break; // Scannable, Connectable
                case 0x01: packet_type_str = "ADV_DIRECT_IND"; break; // Connectable directed
                case 0x02: packet_type_str = "ADV_SCAN_IND"; is_primary_adv = true; break; // Scannable, Non-connectable
                case 0x03: packet_type_str = "ADV_NONCONN_IND"; is_primary_adv = true; break; // Non-scannable, Non-connectable
                case 0x04: packet_type_str = "SCAN_RSP"; break; // Scan Response (Shouldn't contain data now)
                default: break;
            }

            printf("%s AP: Received %s from BORUS %s RSSI: %d\n", timestamp_str, packet_type_str, addr, (int8_t)info->data[info->length]);

            // --- Process Data only if it's a primary ADV packet ---
            if (is_primary_adv) {
                uint8_t *adv_data = info->data;
                int adv_len = info->length;
                int current_pos = 0;
                bool found_mfr_data = false;

                // Parse AD Structures in the primary packet
                while (current_pos < adv_len) {
                    uint8_t field_len = adv_data[current_pos];
                    if (field_len == 0 || (current_pos + 1 + field_len) > adv_len) {
                        fprintf(stderr, "AP: Malformed AD structure in primary ADV at pos %d\n", current_pos);
                        break;
                    }
                    uint8_t field_type = adv_data[current_pos + 1];
                    uint8_t *field_payload = &adv_data[current_pos + 2];
                    uint8_t payload_len = field_len - 1;

                    // Look for Manufacturer Specific Data (0xFF)
                    if (field_type == 0xFF) {
                        // printf("AP: Found Manufacturer Data in %s (Payload Len %u)\n", packet_type_str, payload_len);
                        if (payload_len == ENC_ADV_PAYLOAD_LEN) {
                            found_mfr_data = true;
                            uint8_t *nonce = field_payload;
                            uint8_t *ciphertext = field_payload + NONCE_LEN;
                            uint8_t plaintext[SENSOR_DATA_PACKET_SIZE];

                            int decrypt_ret = decrypt_sensor_block_ap(aes_key, nonce, ciphertext, plaintext);

                            if (decrypt_ret == 0) {
                                // --- Parse Plaintext (same as before) ---
                                int pt_offset = 0;
                                uint8_t encoded_temp = plaintext[pt_offset++];
                                int temp_c = (int)encoded_temp - TEMPERATURE_LOW_LIMIT;

                                uint16_t pressure_offset = plaintext[pt_offset] | (plaintext[pt_offset+1] << 8);
                                pt_offset += 2;
                                uint16_t pressure_x10hpa = pressure_offset + PRESSURE_BASE_HPA_X10;

                                int16_t imu[6];
                                memcpy(imu, &plaintext[pt_offset], sizeof(imu));
                                pt_offset += sizeof(imu);

                                uint32_t ts = plaintext[pt_offset] | (plaintext[pt_offset+1] << 8) |
                                              (plaintext[pt_offset+2] << 16) | (plaintext[pt_offset+3] << 24);
                                pt_offset += 4;

                                uint8_t batt_pct = plaintext[pt_offset++];

                                printf("AP: DECRYPTED -> Temp:%dC Pres:%.1fhPa Batt:%u%% TS:%u IMU:[%d,%d,%d,%d,%d,%d]\n",
                                       temp_c, (float)pressure_x10hpa / 10.0, batt_pct, ts,
                                       imu[0], imu[1], imu[2], imu[3], imu[4], imu[5]);
                                fflush(stdout);

                            } else {
                                fprintf(stderr, "AP: Decryption failed! Code: %d\n", decrypt_ret);
                            }
                        } else {
                             fprintf(stderr, "AP: Mfr data len mismatch in %s (Expected %d, Got %u)\n",
                                    packet_type_str, ENC_ADV_PAYLOAD_LEN, payload_len);
                        }
                        break; // Found Mfr data, stop parsing ADs
                    }
                    current_pos += (1 + field_len);
                } // end while(parsing primary AD)

                if (!found_mfr_data) {
                    printf("AP: Manufacturer data (0xFF with sensor payload) not found in %s.\n", packet_type_str);
                }

            } else if (info->evt_type == 0x04) {
                // Scan Response received - We don't expect sensor data here anymore
                printf("AP: Received SCAN_RSP from BORUS (Ignoring data as per new design).\n");
            }

            // Found BORUS, break from processing more reports in this HCI event
            break;

        } // end if(target_mac)

        // Move to the next report structure in the HCI event
        offset = info->data + info->length + 1;
    } // end while(reports_count--)
} // end process_scan_packet


int main()
{
    int ret;
    srand(time(NULL));

    // --- HCI Device Initialization ---
    printf("AP: Opening HCI device...\n");
    device = hci_open_dev(1); if (device < 0) device = hci_open_dev(0);
    if (device < 0) { perror("AP: Failed to open any HCI device."); return 1; }
    printf("AP: Using device %d\n", device); // Check which one is used

    int flags = fcntl(device, F_GETFL, 0);
    if (flags == -1 || fcntl(device, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("AP: Failed to set socket non-blocking"); hci_close_dev(device); return 1;
    }
    printf("AP: HCI device opened and set to non-blocking.\n");

    // --- Initial BLE Configuration ---
    printf("AP: Configuring initial BLE parameters...\n");
    if (set_advertising_parameters(device) < 0) goto ap_cleanup;
    if (set_advertising_data(device, AP_ADV_DATA_VALUE) < 0) goto ap_cleanup;
    if (set_scan_parameters(device) < 0) goto ap_cleanup; // Set scan params for active scan

    // Set HCI event filter for LE Meta Events
    struct hci_filter nf;
    hci_filter_clear(&nf);
    hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
    hci_filter_set_event(EVT_LE_META_EVENT, &nf);
    if (setsockopt(device, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0) {
        perror("AP: Could not set HCI filter"); goto ap_cleanup;
    }
    printf("AP: HCI filter set.\n");

    // --- Main Loop ---
    time_t last_adv_time = 0;
    int next_adv_interval = 0;
    bool is_scanning = false;
    bool is_advertising = false;

    printf("AP: Starting main loop (Scan + Periodic Advertise)...\n");

    while (1) {
        time_t now = time(NULL);

        // --- Periodic Advertising Burst ---
        if (!is_advertising && (now >= last_adv_time + next_adv_interval)) {
            // printf("AP: [%s] Triggering advertising burst...\n", ctime(&now)); // Can be noisy
			int interval_for_following_burst = BASE_ADV_INTERVAL_S + (rand() % (JITTER_S + 1));
			uint16_t time_to_next_burst_s = (uint16_t)interval_for_following_burst; 
			

            if (is_scanning) { // Stop scan before advertising
                if (set_scan_enable(device, false, true) == 0) {
                    is_scanning = false; usleep(20000);
                } else { /* Log warning */ }
            }

            if (set_advertise_enable(device, true) == 0) { // Start burst
                 is_advertising = true; usleep(ADV_BURST_DURATION_MS * 1000);
                 set_advertise_enable(device, false); // Stop burst
                 is_advertising = false;
                 // printf("AP: Advertising burst finished.\n"); // Can be noisy
            } else { /* Log warning */ is_advertising = false; }

            last_adv_time = time(NULL);
            next_adv_interval = BASE_ADV_INTERVAL_S + (rand() % (JITTER_S + 1));
            printf("AP: Next advertising burst in %d seconds.\n", next_adv_interval);
        }

        // --- Continuous Scanning (if not advertising) ---
        if (!is_scanning && !is_advertising) {
             if (set_scan_enable(device, true, false) == 0) { // Enable scan, filter duplicates
                is_scanning = true;
             } else { fprintf(stderr, "AP: Error: Failed scan enable! Retrying.\n"); sleep(5); continue; }
        }

        // Process packets if scanning
        if (is_scanning) {
            uint8_t buf[HCI_MAX_EVENT_SIZE];
            int len = read(device, buf, sizeof(buf));

            if (len < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) { perror("AP: HCI read error"); sleep(1); }
            } else if (len > 0) {
                process_scan_packet(buf, len);
            }
        }

        // Yield CPU slightly
        // usleep(10000); // 10ms sleep

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
