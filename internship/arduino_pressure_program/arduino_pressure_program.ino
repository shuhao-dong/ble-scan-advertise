
// Built-in library for barometer
#include <Arduino_LPS22HB.h>

// Note - do not include the humidity sensor as well!!
// Including the library for the arduino HTS221 causes weird behaviour
// This is likely due to the thermometer being shared between the humidity sensor and the pressure sensor

// Used to filter the output to reduce noise
float p_output = 0.0;
const float alpha = 0.1;

void setup() {
  // Initialize digital pin LED_BUILTIN as an output.
  pinMode(LED_BUILTIN, OUTPUT);
  // Initialize serial output for communication with NUC
  Serial.begin(9600);
  // Initialzie barometer
  BARO.begin();
}

void loop() {
  // Run loop once per second
  int loop_start_time = millis();
  if ((millis() - loop_start_time) < 1000) {
    digitalWrite(LED_BUILTIN, HIGH);                              // Turn the LED on
    p_output=(alpha*BARO.readPressure())+((1.0-alpha)*p_output);  // Filter pressure value to reduce noise
    Serial.println(String(p_output,4));                           // Print up to 4 decimal points of pressure output to serial connection
    delay(400);                                                   // Leave LED on for short time
    digitalWrite(LED_BUILTIN, LOW);                               // Turn the LED off
    delay(400);                                                   // Leave LED off for short time
  }
}
