#!/usr/bin/env python3
"""Extract the pre-SSL init sequence (incl. HP's two firmware patches) from a usblog.c trace of HP's
binary, for tools/ssl_session.py. One-time; the output stays local (captures/ is gitignored).

    # trace one HP run on a freshly reset sensor (no swipe needed, kill it after a few seconds):
    sudo VFSLOG=/tmp/usb.log LD_PRELOAD=$PWD/lib/usblog.so LD_LIBRARY_PATH=$PWD/lib \
        timeout -s KILL 6 bin/validity-sensor-unlocked getprintwait -doinit
    python3 trace_to_init.py /tmp/usb.log ../captures/init_cmds.json
"""
import json
import sys


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    outs = [l.split("data=", 1)[1].strip() for l in open(sys.argv[1]) if "OUT ep=01" in l and "data=" in l]
    try:
        end = next(i for i, h in enumerate(outs) if h.startswith("113c00"))   # the ClientHello tunnel
    except StopIteration:
        sys.exit("no ClientHello in the trace: let HP's binary run longer")
    # 1a (UnloadPatch) only appears when the sensor still had a patch loaded; ssl_session.py starts clean
    init = [h for h in outs[:end] if h != "1a"]
    json.dump(init, open(sys.argv[2], "w"))
    print("init:", " ".join(h[:2] for h in init), "->", sys.argv[2])


if __name__ == "__main__":
    main()
