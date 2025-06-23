# BLE Scan and Advertise
Use Bluez library to scan and advertise in extended advertisement mode concurrently. The received data will be published via MQTT to a broker.

## Credits

This program is based off of code by Damian Kołakowski here https://github.com/damian-kolakowski/intel-edison-playground/blob/master/scan.c
This program is based on code by David G. Young at: https://github.com/davidgyoung/ble-scanner/blob/master/scanner.c

Please follow the instructions in the above link to install necessary libraries

## Test Platform
Raspberry Pi 5 running Debian GNU/Linux version 12, with Python 3.11.2. nRF52840 dongle is used as the Bluetooth dongle to receive extended advertisement. The dongle is flashed with the HCI controller firmware at: https://github.com/shuhao-dong/BORUS

## Install Dependencies

You have to install the following libraries before you can use the source code scan_adv.c

    sudo apt-get install libssl-dev libbluetooth-dev libmosquitto-dev mosquitto-clients

## Configure Random Static Address

The RPi acts as both observer and broadcaster, meaning it will also advertise back to the wearable to let the wearable confirm its current status.
In this advertising process, we explicitly configured the RPi with the following MAC address format:

    C0:54:52:53:XX:XX

C0 denotes a random static address (this is a must), 54:52:53 is the ASCII code for TRS (short for TORUS), the last two bytes can be arranged as needed. In test phase, this can be incrementing number. In deployment phase, this can be house number:participant number/wearable number etc. 


# JSON Schema for Wearable Packets
This schema defines the structure of MQTT messages sent by the BLE scanner: internship\torus_wearable_packet_JSON

