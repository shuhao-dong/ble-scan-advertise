# BLE Scan and Advertise
Use Bluez library to scan and advertise concurrently

## Credits

This program is based off of code by Damian Kołakowski here https://github.com/damian-kolakowski/intel-edison-playground/blob/master/scan.c
This program is based on code by David G. Young at: https://github.com/davidgyoung/ble-scanner/blob/master/scanner.c

Please follow the instructions in the above link to install necessary libraries

## Test Platform
Raspberry Pi 5 running Debian GNU/Linux version 12

## Install Dependencies

You have to install the following libraries before you can use this code

    sudo apt-get install libssl-dev libbluetooth-dev

Use with this firmware version to receive the extended advertisement packets: https://github.com/shuhao-dong/BORUS/tree/feature/ext-adv-sync

