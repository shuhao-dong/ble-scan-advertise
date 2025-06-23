# 1. Overview

This is the project code for TORUS using standard C library to receive extended advertisement from TORUS wearable, decrypt package, format JSON and publish to the MQTT broker. The code is primarily tested on a Raspberry Pi 5 running either Ubuntu or Raspberry Pi OS. 

    BORUS/
    └── internship/                         # Internship workspace
        ├── docs                            # JSON schema and topic design 
        └── torus_wearable_packet_JSON      # JSON schema and example JSON packet

# 2. BLE Scan and Advertise

Use Bluez library to scan and advertise in extended advertisement mode concurrently. The received data will be published via MQTT to a broker.

## 2.1 Credits

This program is based off of code by Damian Kołakowski here https://github.com/damian-kolakowski/intel-edison-playground/blob/master/scan.c
This program is based on code by David G. Young at: https://github.com/davidgyoung/ble-scanner/blob/master/scanner.c

Please follow the instructions in the following link to install necessary libraries

## 2.2 Test Platform

Raspberry Pi 5 running Debian GNU/Linux version 12, with Python 3.11.2. nRF52840 dongle is used as the Bluetooth dongle to receive extended advertisement. The dongle is flashed with the HCI controller firmware at: https://github.com/shuhao-dong/BORUS. This is a private repository access upon request only. 

## 2.3 Install Dependencies

You have to install the following libraries before you can compile the source code scan_adv.c

    sudo apt-get install libssl-dev libbluetooth-dev libmosquitto-dev mosquitto-clients

## 2.4 Configure Random Static Address

The RPi acts as both observer and broadcaster, meaning it will also advertise back to the wearable to let the wearable confirm its current status.
In this advertising process, we explicitly configured the RPi with the following MAC address format:

    C0:54:52:53:XX:XX

C0 denotes a random static address (this is a must), 54:52:53 is the ASCII code for TRS (short for TORUS), the last two bytes can be arranged as needed. In the test phase, this can be an incrementing number. In deployment phase, this can be house number/participant number/wearable number etc. 

## 2.5 Use the Compiled Code 

Run the below command to compile and generate the excutable file "scan_publish" to your specified directory.

    cc <path-to-source/scan_adv.c> -o <path-to-excutable/scan_publish> -lbluetooth -lssl -lcrypto -lmosquitto

Once done, you can navigate to the output directory and run:

    sudo <path-to-your-scan_publish/scan_publish> 0 or 1

Select the index 0 or 1 based on the index of the nRF52840 dongle HCI controller. If you select a wrong index, the error will report No support to set up current parameter. 

# 3. JSON Schema for Wearable Packets

This schema defines the structure of MQTT messages sent by the BLE scanner: internship\torus_wearable_packet_JSON

Credit to @talliskinrade and @JoelDunnett


