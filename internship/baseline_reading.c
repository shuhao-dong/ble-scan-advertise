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
        // list all ports
        sp_list_ports(&ports);
        for (int i = 0; ports[i]; i++)
        {
            // select valid ports
            const char *name = sp_get_port_name(ports[i]);
            if (strstr(name, "ttyACM") ||
                strstr(name, "ttyUSB") ||
                strstr(name, "COM"))
            {
                // test ports and connect
                if (sp_open(ports[i], SP_MODE_READ) == SP_OK)
                {
                    sp_set_baudrate(ports[i], BAUD_RATE);
                    sp_free_port_list(ports);
                    return ports[i];
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
        sleep(1);
    }
}

int main()
{
    // create + connect MQTT client
    MQTTClient client;
    MQTTClient_create(&client, BROKER_URI, CLIENT_ID, MQTTCLIENT_PERSISTENCE_NONE, NULL);
    mqtt_connect(&client);

    // connect to arduino
    struct sp_port *port = establish_port();

    char buf[BUF_LEN];
    char json_buf[JSON_LEN];

    while (1)
    {
        char *p = json_buf;
        int left = JSON_LEN;

        int n = sp_nonblocking_read(port, buf, BUF_LEN - 1);
        // disconnect + reconnect serial on failure or no data
        if (n <= 0)
        {
            sp_close(port);
            port = establish_port();
            continue;
        }
        buf[n] = '\0';
        float value = atof(buf);

        // get epoch time
        time_t now = time(NULL);
        // format
        struct tm tm;
        gmtime_r(&now, &tm);
        char ts[32];
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);

        // // build JSON object
        // cJSON *root = cJSON_CreateObject();                                 //empty object
        // cJSON_AddStringToObject(root, "timestamp", ts);                     //timestamp at root
        // cJSON *measurements = cJSON_AddArrayToObject(root, "measurements"); //measurements array
        // cJSON *pressure = cJSON_CreateObject();                             //pressure object
        // cJSON_AddStringToObject(pressure, "property", "base_press");        //add pressure properties
        // cJSON_AddNumberToObject(pressure, "value", value);                  //<
        // cJSON_AddStringToObject(pressure, "unit", "hPa");                   //<
        // cJSON_AddItemToArray(measurements, pressure);                       //add pressure to measurements
        // char *json_str = cJSON_PrintUnformatted(root);                      //serialse

        int w = snprintf(p, left,
                         "{"
                         "\"timestamp\":\"%s\","
                         "\"measurements\":[",
                         ts);
        p += w;
        left -= w;

        w = snprintf(p, left,
                     "{\"property\":\"base_pressure\",\"value\":%.2f,\"unit\":\"hPa\"}",
                     value);
        p += w;
        left -= w;

        snprintf(p, left, "]}\n");

        fputs(json_buf, stdout); // print to terminal
        fflush(stdout);

        // publish message
        MQTTClient_message msg = MQTTClient_message_initializer;
        msg.payload = json_buf;
        msg.payloadlen = strlen(json_buf);
        msg.qos = 1;
        MQTTClient_deliveryToken token;
        // disconnect + reconnect MQTT on failure
        if (MQTTClient_publishMessage(client, TOPIC, &msg, &token) != MQTTCLIENT_SUCCESS)
        {
            MQTTClient_disconnect(client, 1000);
            mqtt_connect(&client);
            MQTTClient_publishMessage(client, TOPIC, &msg, &token);
        }
        MQTTClient_waitForCompletion(client, token, 1000);

        // cJSON_Delete(root);
        // free(json_str);
    }
    MQTTClient_disconnect(client, 1000);
    MQTTClient_destroy(&client);
    sp_close(port);
    return 0;
}