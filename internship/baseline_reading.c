#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
// #include <cjson/cJSON.h>
#include <MQTTClient.h>
#include <libserialport.h>

#define BROKER_URI "192.168.88.251:1883"
#define CLIENT_ID "baseline_arduino"
#define TOPIC "borus/wearable"
#define BAUD_RATE 9600
#define BUF_LEN 32
#define JSON_LEN 256

// establish serial connection with Arduino
struct sp_port *establish_port()
{
    struct sp_port **ports;
    while (1)
    {
        printf("Scanning for serial ports...\n");
        // list all ports
        sp_list_ports(&ports);
        for (int i = 0; ports[i]; i++)
        {
            // select valid ports
            const char *name = sp_get_port_name(ports[i]);
            printf("Checking port: %s\n", name);
            if (strstr(name, "ttyACM") ||
                strstr(name, "ttyUSB") ||
                strstr(name, "COM"))
            {
                printf("Attempting to open port: %s\n", name);
                // test ports and connect
                struct sp_port *selected = ports[i];
                if (sp_open(ports[i], SP_MODE_READ) == SP_OK)
                {
                    printf("Connected to %s\n", name);
                    sp_set_baudrate(selected, BAUD_RATE);
                    sp_free_port_list(ports);
                    return selected;
                }
                else
                {
                    printf("Failed to open port: %s\n", name);
                }
            }
        }
        sp_free_port_list(ports);
        sleep(1);
    }
}

// establish connection with MQTT broker
void mqtt_connect(MQTTClient *client)
{
    MQTTClient_connectOptions opts = MQTTClient_connectOptions_initializer;
    opts.keepAliveInterval = 20;
    opts.cleansession = 1;
    while (MQTTClient_connect(*client, &opts) != MQTTCLIENT_SUCCESS)
    {
        printf("MQTT connect failed with code. Retrying... \n");
        sleep(1);
    }
    printf("MQTT connected successfully.\n");
}

int main()
{
    printf("Creating MQTT client for broker %s\n", BROKER_URI);
    // create + connect MQTT client
    MQTTClient client;
    MQTTClient_create(&client, BROKER_URI, CLIENT_ID, MQTTCLIENT_PERSISTENCE_NONE, NULL);
    mqtt_connect(&client);

    // connect to arduino
    struct sp_port *port = establish_port();

    if (!port)
    {
        printf("ERROR: establish_port returned NULL\n");
        return 1;
    }
    printf("Port seccessfully returned to main\n");

    char buf[BUF_LEN];
    char json_buf[JSON_LEN];

    while (1)
    {
        static char line_buf[BUF_LEN];
        static int pos = 0;

        unsigned char byte;
        while (sp_nonblocking_read(port, &byte, 1) == 1)
        {
            if (byte == '\n')
            {
                line_buf[pos] = '\0';
                pos = 0;

                printf("Raw serial input: '%s'\n", line_buf);
                float value = 0;
                if (sscanf(line_buf, "%f", &value) != 1)
                {
                    fprintf(stderr, "Failed to parse value from: '%s'\n", line_buf);
                    continue;
                }

                printf("Parsed value: %.2f\n", value);

                // get timestamp
                time_t now = time(NULL);
                struct tm tm;
                gmtime_r(&now, &tm);
                char ts[32];
                strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);

                // build JSON string
                char *p = json_buf;
                int left = JSON_LEN;

                int w = snprintf(p, left,
                                 "{"
                                 "\"timestamp\":\"%s\","
                                 "\"measurements\":[",
                                 ts);
                if (w < 0 || w >= left)
                    continue;
                p += w;
                left -= w;

                w = snprintf(p, left,
                             "{\"property\":\"base_pressure\",\"value\":%.2f,\"unit\":\"hPa\"}",
                             value);
                if (w < 0 || w >= left)
                    continue;
                p += w;
                left -= w;

                snprintf(p, left, "]}\n");

                printf("Final JSON payload: %s\n", json_buf);

                // publish message
                MQTTClient_message msg = MQTTClient_message_initializer;
                msg.payload = json_buf;
                msg.payloadlen = strlen(json_buf);
                msg.qos = 1;
                MQTTClient_deliveryToken token;
                if (MQTTClient_publishMessage(client, TOPIC, &msg, &token) != MQTTCLIENT_SUCCESS)
                {
                    MQTTClient_disconnect(client, 1000);
                    mqtt_connect(&client);
                    MQTTClient_publishMessage(client, TOPIC, &msg, &token);
                }
                MQTTClient_waitForCompletion(client, token, 1000);

                break; // break out of byte-reading loop to restart cleanly
            }
            else if (byte >= 32 && byte <= 126 && pos < BUF_LEN - 1)
            {
                line_buf[pos++] = byte;
            }
            else if (byte == '\r')
            {
                continue; // ignore CR
            }
        }
    }

    MQTTClient_disconnect(client, 1000);
    MQTTClient_destroy(&client);
    sp_close(port);
    return 0;
}