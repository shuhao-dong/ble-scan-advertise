CC		:= gcc
CFLAGS	:= -std=c11 -Wall'pkg-config --cflags libserialport cjson paho-mqtt3c'
LDFLAG	:= 'pkg-config --libs libserialport cjson paho-mqtt3c'

SRC		:= baseline_reading.c
TARGET	:= baseline_reading

all: bridge

bridge: baseline_reading.c
	gcc -std=c11 -Wall baseline_reading.c -o bridge \
	$(shell pkg-config --cflags --libs libserialport libcjson libpaho-mqtt3c)

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean