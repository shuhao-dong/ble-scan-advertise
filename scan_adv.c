// Copyright (c) 2021 David G. Young
// Copyright (c) 2015 Damian Kołakowski. All rights reserved.

// cc scan_adv.c -lbluetooth -o scan_adv
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

int device;

const char target_mac[] = "FC:49:49:27:11:81";
// const char target_mac[] = "FA:F0:07:00:D8:E0";


/**
 * @brief Send request to HCI controller
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

void set_advertising_parameters(int device)
{
    le_set_advertising_parameters_cp adv_params_cp;
    memset(&adv_params_cp, 0, sizeof(adv_params_cp));
    adv_params_cp.min_interval = htobs(0x0800);     // Minimum advertising interval
    adv_params_cp.max_interval = htobs(0x0801);     // Maximum advertising interval
    adv_params_cp.advtype = 0x03;                   // Connectable undirected advertising
    adv_params_cp.own_bdaddr_type = 0x00;           // Public device address
    adv_params_cp.chan_map = 0x07;                  // All channels
    adv_params_cp.filter = 0x00;                    // Allow scan from any device 

    uint8_t status;
    struct hci_request adv_params_rq = ble_hci_request(OCF_LE_SET_ADVERTISING_PARAMETERS, 
                    LE_SET_ADVERTISING_PARAMETERS_CP_SIZE, 
                    &status, 
                    &adv_params_cp);
    int ret = hci_send_req(device, &adv_params_rq, 1000);
    if (ret < 0){
        perror("Failed to set advertising parameters"); 
    }

}

void set_advertising_data(int device, uint8_t my_value)
{
    le_set_advertising_data_cp adv_data_cp;
    memset(&adv_data_cp, 0, sizeof(adv_data_cp));

    uint8_t index = 0;

    adv_data_cp.data[index++] = 4;      // Length of this AD structure
    adv_data_cp.data[index++] = 0xFF;   // Manufacturer Specific Data
    adv_data_cp.data[index++] = my_value;

    // Set the total length of advertising data
    adv_data_cp.length = index;

    uint8_t status;
    struct hci_request adv_data_rq = ble_hci_request(OCF_LE_SET_ADVERTISING_DATA, index+1, &status, &adv_data_cp);
    int ret = hci_send_req(device, &adv_data_rq, 1000);
    if (ret < 0){
        perror("Failed to set advertising data"); 
    }
}

/**
 * @brief Enable or disable advertising
 * 
 * @param enable_adv Set 1 to enable, 0 to disable
 * @param device BLE device
 */
void enable_advertising(int device, uint8_t enable_adv)
{
    le_set_advertise_enable_cp advertise_cp;
    memset(&advertise_cp, 0, sizeof(advertise_cp));
    advertise_cp.enable = enable_adv; // Enable advertising

    uint8_t status;
    struct hci_request enable_adv_rq = ble_hci_request(OCF_LE_SET_ADVERTISE_ENABLE, 
                    LE_SET_ADVERTISE_ENABLE_CP_SIZE,
                    &status,
                    &advertise_cp); 
    int ret = hci_send_req(device, &enable_adv_rq, 1000);
    if (ret < 0){
        perror("Failed to enable advertising"); 
    }

    printf("Advertising ...\n");
}

void enable_scanning(int device)
{
    int ret;
    uint8_t status;

    // Set BLE scan parameters
    le_set_scan_parameters_cp scan_params_cp;
	memset(&scan_params_cp, 0, sizeof(scan_params_cp));
	scan_params_cp.type 			= 0x00;
	scan_params_cp.interval 		= htobs(0x0030);
	scan_params_cp.window 			= htobs(0x0030);
	scan_params_cp.own_bdaddr_type 	= 0x00; // Public Device Address (default).
	scan_params_cp.filter 			= 0x00; // Accept all.

	struct hci_request scan_params_rq = ble_hci_request(OCF_LE_SET_SCAN_PARAMETERS, LE_SET_SCAN_PARAMETERS_CP_SIZE, &status, &scan_params_cp);

	ret = hci_send_req(device, &scan_params_rq, 1000);
	if ( ret < 0 ) {
		hci_close_dev(device);
		perror("Failed to set scan parameters data.");
		exit(1); 
	}

    // Set BLE events report mask.
	le_set_event_mask_cp event_mask_cp;
	memset(&event_mask_cp, 0, sizeof(le_set_event_mask_cp));
	int i = 0;
	for ( i = 0 ; i < 8 ; i++ ) event_mask_cp.mask[i] = 0xFF;

	struct hci_request set_mask_rq = ble_hci_request(OCF_LE_SET_EVENT_MASK, LE_SET_EVENT_MASK_CP_SIZE, &status, &event_mask_cp);
	ret = hci_send_req(device, &set_mask_rq, 1000);
	if ( ret < 0 ) {
		hci_close_dev(device);
		perror("Failed to set event mask.");
		exit(1);
	}

    // Enable scanning
    le_set_scan_enable_cp scan_cp;
	memset(&scan_cp, 0, sizeof(scan_cp));
	scan_cp.enable 		= 0x01;	// Enable flag.
	scan_cp.filter_dup 	= 0x00; // Filtering disabled.

	struct hci_request enable_adv_rq = ble_hci_request(OCF_LE_SET_SCAN_ENABLE, LE_SET_SCAN_ENABLE_CP_SIZE, &status, &scan_cp);

	ret = hci_send_req(device, &enable_adv_rq, 1000);
	if ( ret < 0 ) {
		hci_close_dev(device);
		perror("Failed to enable scan.");
		exit(1);
	}

    // Get Results.
	struct hci_filter nf;
	hci_filter_clear(&nf);
	hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
	hci_filter_set_event(EVT_LE_META_EVENT, &nf);
	if ( setsockopt(device, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0 ) {
		hci_close_dev(device);
		perror("Could not set socket options\n");
		exit(1);
	}
}

void disable_scanning(int device)
{
    int ret;
    uint8_t status;

    // Enable scanning
    le_set_scan_enable_cp scan_cp;
	memset(&scan_cp, 0, sizeof(scan_cp));
	scan_cp.enable 		= 0x00;	// Enable flag.

	struct hci_request enable_adv_rq = ble_hci_request(OCF_LE_SET_SCAN_ENABLE, LE_SET_SCAN_ENABLE_CP_SIZE, &status, &scan_cp);

	ret = hci_send_req(device, &enable_adv_rq, 1000);
	if ( ret < 0 ) {
		hci_close_dev(device);
		perror("Failed to disable scan.");
		exit(1);
	}
}

void scan_for_advertisements(int device, int duration, int reset)
{
    uint8_t buf[HCI_MAX_EVENT_SIZE];
	evt_le_meta_event * meta_event;
	le_advertising_info * info;
	int len;
	int count = 0;

	const int max_count = -1;

    time_t start_time = time(NULL); 

	// Keep scanning until the timeout is triggered or we have seen lots of advertisements.  Then exit.
	// We exit in this case because the scan may have failed or stopped. Higher level code can restart
	while ( (count < max_count || max_count <= 0) && (time(NULL) - start_time) < duration )
	{
		len = read(device, buf, sizeof(buf));
		if ( len >= HCI_EVENT_HDR_SIZE )
		{
			meta_event = (evt_le_meta_event*)(buf+HCI_EVENT_HDR_SIZE+1);
			if ( meta_event->subevent == EVT_LE_ADVERTISING_REPORT )
			{
				count++;
				
                if (reset != 0){
                    start_time = time(NULL); 
                }

				// Get current time
				time_t now = time(NULL);
				char timestamp[20];
				strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

				// print results
				uint8_t reports_count = meta_event->data[0];
				void * offset = meta_event->data + 1;
				while ( reports_count-- )
				{
					info = (le_advertising_info *)offset;
					char addr[18];
					ba2str( &(info->bdaddr), addr);
					if (strcmp(addr, target_mac) == 0){
						printf("%s %s %d", timestamp, addr, (int8_t)info->data[info->length]);
						for (int i = 0; i < info->length; i++){
							// printf(" %02X ", (unsigned char)info->data[i]);
							
							/* Parse temperature data at byte 2 and byte 3 */
							if (i == 2 && (i + 1) < info->length){
								float temperature = (uint16_t)(info->data[i] | (info->data[i+1] << 8)) / 100.0f;
								printf(" Temp:%.2f", temperature); 
							}else if (i == 4 && (i + 3) < info->length){
								float pressure = (uint32_t)(info->data[i] |
															(info->data[i+1] << 8) | 
												  			(info->data[i+2] << 16) |
												  			(info->data[i+3] << 24)) / 100.0f; 
								printf(" Pres:%.2f", pressure); 
							}else if (i == 24){
								int button_value = (uint8_t)(info->data[i]);
								printf(" Button: %d", button_value); 
							}
						}
						printf("\n");
					}
					offset = info->data + info->length + 2;
				}
			}
		}
        else{
            usleep(10000);
        }
	}
    printf("Scan duration reached, exiting scan loop\n");
    disable_scanning(device); 
}

int main()
{
	int ret, status;

	// Get HCI device.
	device = hci_open_dev(1);
	if ( device < 0 ) {
		device = hci_open_dev(0);
		if (device >= 0) {
   		printf("Using hci0\n");
		}
	}
	else {
   		printf("Using hci1\n");
	}

	if ( device < 0 ) {
		perror("Failed to open HCI device.");
		return 0;
	}

	// Set device socket to non-blocking mode
    int flags = fcntl(device, F_GETFL, 0); 
    fcntl(device, F_SETFL, flags | O_NONBLOCK); 

    while(1){
        // Disable scanning if active
        disable_scanning(device);

        // Advertising
        set_advertising_parameters(device);
        set_advertising_data(device, 12);
        enable_advertising(device, 1); 

        // sleep(30);

        // enable_advertising(device, 0);

        enable_scanning(device);

        scan_for_advertisements(device, 30, 0); 
    }

    hci_close_dev(device);
    return 0; 
}
