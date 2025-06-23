# BLE Scan and Advertise
Use Bluez library to scan and advertise concurrently

## Credits

This program is based off of code by Damian Kołakowski here https://github.com/damian-kolakowski/intel-edison-playground/blob/master/scan.c
This program is based on code by David G. Young at: https://github.com/davidgyoung/ble-scanner/blob/master/scanner.c

Please follow the instructions in the above link to install necessary libraries

## Test Platform
Raspberry Pi 5 running Debian GNU/Linux version 12, with Python 3.11.2

## Install Dependencies

You have to install the following libraries before you can use the source code scan_adv.c

    sudo apt-get install libssl-dev libbluetooth-dev libmosquitto-dev mosquitto-clients

Under the directory mqtt-publisher, there are two python files that: 

(1) Test C wrapper subprocess
(2) Test publisher code

To run either python, you will need to install the mqtt library in your virtual environment 

    pip install paho-mqtt

## Configure Random Static Address

The RPi acts as both observer and broadcaster, meaning it will also advertise back to the wearable to let the wearable confirm its current status.
In this advertising process, we explicitly configured the RPi with the following MAC address format:

    C0:54:52:53:XX:XX

C0 denotes a random static address (this is a must), 54:52:53 is the ASCII code for TRS (short for TORUS), the last two bytes can be arranged as needed. In test phase, this can be incrementing number. In deployment phase, this can be house number:participant number/wearable number etc. 


# JSON Schema for Wearable Packets
This schema defines the structure of MQTT messages sent by the BLE scanner: https://github.com/talliskinrade/torus_wearable_packet.git

