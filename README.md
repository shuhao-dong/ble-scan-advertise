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


# 4. Expected Outcome
Running the scanner should produce decryted JSON packets published via MQTT.
Example output:
    
    {"base_timestamp":"2025-07-23T14:42:38Z","wearable_id":"EE:54:52:53:00:01","gateway_id":"C0:54:52:53:00:00","measurement_data":{"state":[{"property":"temperature","value":25,"unit":"degC"},{"property":"pressure","value":1014.40,"unit":"hPa"},{"property":"rssi","value":-60,"unit":"dBm"}],"IMU_batch":[{"acc":[-7.64,-5.37,-1.77],"acc_unit":"m/s^2","gyro":[0.01,0.04,-0.06],"gyro_unit":"rad/s","ts":4624},{"acc":[-7.69,-5.35,-1.78],"acc_unit":"m/s^2","gyro":[0.00,0.08,-0.05],"gyro_unit":"rad/s","ts":4634},{"acc":[-7.73,-5.36,-1.86],"acc_unit":"m/s^2","gyro":[-0.02,0.14,-0.03],"gyro_unit":"rad/s","ts":4644},{"acc":[-7.79,-5.36,-1.93],"acc_unit":"m/s^2","gyro":[-0.03,0.17,-0.03],"gyro_unit":"rad/s","ts":4653},{"acc":[-7.81,-5.36,-1.96],"acc_unit":"m/s^2","gyro":[-0.03,0.16,-0.04],"gyro_unit":"rad/s","ts":4663},{"acc":[-7.80,-5.40,-2.02],"acc_unit":"m/s^2","gyro":[-0.02,0.11,-0.06],"gyro_unit":"rad/s","ts":4673},{"acc":[-7.76,-5.52,-2.04],"acc_unit":"m/s^2","gyro":[0.00,0.07,-0.07],"gyro_unit":"rad/s","ts":4683},{"acc":[-7.79,-5.69,-1.98],"acc_unit":"m/s^2","gyro":[0.04,0.05,-0.11],"gyro_unit":"rad/s","ts":4693},{"acc":[-7.80,-5.77,-1.89],"acc_unit":"m/s^2","gyro":[0.07,0.03,-0.12],"gyro_unit":"rad/s","ts":4703},{"acc":[-7.81,-5.85,-1.87],"acc_unit":"m/s^2","gyro":[0.10,0.03,-0.12],"gyro_unit":"rad/s","ts":4713},{"acc":[-7.82,-5.98,-1.84],"acc_unit":"m/s^2","gyro":[0.12,0.07,-0.11],"gyro_unit":"rad/s","ts":4723},{"acc":[-7.88,-6.08,-1.85],"acc_unit":"m/s^2","gyro":[0.13,0.12,-0.08],"gyro_unit":"rad/s","ts":4733},{"acc":[-7.97,-6.13,-1.89],"acc_unit":"m/s^2","gyro":[0.15,0.18,-0.03],"gyro_unit":"rad/s","ts":4742},{"acc":[-8.01,-6.15,-1.95],"acc_unit":"m/s^2","gyro":[0.18,0.23,0.02],"gyro_unit":"rad/s","ts":4752}]},"monitoring":[{"property":"battery_voltage","value":4000,"unit":"mV"},{"property":"soc_temperature","value":26,"unit":"degC"},{"property":"npm_status","value":0}]}

