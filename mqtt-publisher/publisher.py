import json, subprocess, sys, signal, time
import paho.mqtt.client as mqtt

BROKER = "192.168.1.100"
TOPIC = "borus/sensor"
SCANNER = "./scan_pub"

running = True

def handle_sig(sig, frame):
    global running
    running = False
signal.signal(signal.SIGINT, handle_sig)
signal.signal(signal.SIGTERM, handle_sig)

cli = mqtt.Client(
        client_id="rpi-wrapper"
)

cli.connect(BROKER, 1883, 60)
cli.loop_start()

p = subprocess.Popen(["sudo", "-n", SCANNER, "1"], stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True, bufsize=1)

try:
    for line in p.stdout:
        if not running:
            break
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            print("Bad JSON:", line, file=sys.stderr)
            continue
        cli.publish(TOPIC, line, qos=1)
        print(time.strftime("%H:%M:%S"), payload)
finally:
    running = False
    p.terminate()
    cli.loop_stop
    cli.disconnect()