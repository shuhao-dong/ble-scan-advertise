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

## Running the First Time

Before you can run this code, firstly verify your BlueZ version by running

    bluetoothctl

The code is tested with BlueZ version 5.82 on Raspberry Pi OS devices and BlueZ version 5.72 on Ubuntu devices.
Next, you will have to verify is the USB device is successfully enumerated by runing lsusb, you should be able to see "NordicSemiconductor USB-DEV".
Then, confirm the HCI device is up and running by

    hciconfig

On bus USB, you should be able to see a hci1 with UP RUNNING. If not, then run _**rfkill**_ to make sure the device is not blocked. If blocked, run

    sudo rfkill unblock <id>    # id is the index number you found when running rfkill 

Verify the HCI status by running hciconfig again.
As a final step, you may want to run _**bluetoothctl**_ to register an agent, then run _**list**_, then run _**select**_ to select the device with manufacturer 0059. Finally, run _**power on**_ to power on the controller.
