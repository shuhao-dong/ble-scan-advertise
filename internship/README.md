## internship
This directory contains the work created by Tallis and Joel pertaining to the ble-scan-advertise/ repo on the integration/mqtt-publisher/ branch.

It contains:

## docs/
Containing the collaborative documents created for the JSON Schema (Schema Definitions.docx) and MQTT UNS Topic Design (MQTT Topics.docx).

## torus_wearable_packet_JSON/
Containing the JSON Schema (JSON_test.jsonc) and an example of what a packet from the borus wearable device looks like (Sample_Packet.jsonc).

## baseline_reading.c
Publishes the baseline pressure reading from the arduino via MQTT.
Example raw serial output:
"
101.6200 29.4678

101.6200 29.4711

101.6201 29.4723

"

Example console output:
"
Raw serial input: '101.6161 27.8329'
Parsed value: 101.62
Final JSON payload: {"timestamp":"2025-07-01T16:38:50Z","measurements":[{"property":"base_pressure","value":101.62,"unit":"hPa"}]}
"

Example subscriber output:
borus/wearable {"timestamp":"2025-07-01T16:38:50Z","measurements":[{"property":"base_pressure","value":101.62,"unit":"hPa"}]}

Theres also the possibility to output the baseline temperature as well.