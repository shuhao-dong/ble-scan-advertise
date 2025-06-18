#!/usr/bin/env python3
"""
check_scanner.py       verify that the C scanner subprocess
                       produces well-formed JSON packets
"""

import json, subprocess, pprint, signal, sys

SCANNER = "./scan"          # path to your compiled C programme
running = True

def stop(sig, frame):
    global running
    running = False
signal.signal(signal.SIGINT, stop)
signal.signal(signal.SIGTERM, stop)

# launch the scanner; text=True gives str lines instead of bytes
proc = subprocess.Popen(["sudo", "-n", SCANNER, "1"], stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True, bufsize=1)

pp = pprint.PrettyPrinter(indent=2, width=80)

try:
    for line in proc.stdout:
        if not running:
            break
        line = line.strip()
        if not line:
            continue                      # skip blank lines

        try:
            pkt = json.loads(line)        # validate & convert to dict
        except json.JSONDecodeError as e:
            print("JSON error:", e, "| raw:", line, file=sys.stderr)
            continue

        pp.pprint(pkt)                    # friendly dump
except KeyboardInterrupt:
    pass
finally:
    running = False
    proc.terminate()
    proc.wait()
