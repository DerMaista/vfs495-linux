#!/usr/bin/env python3
"""Pack the sensor's init/setup commands into the single file the libfprint driver reads.

    python3 make_setup_bin.py [CAPTURES_DIR] OUT.bin      (default dir: ../captures)
    sudo install -m600 OUT.bin /var/lib/vfs495/setup.bin

Input: init_cmds.json (runtime/trace_to_init.py) and capture_cmds.json (HP's setup commands, decrypted
from one traced HP session). Both are HP's per-device data; the output stays local, never redistribute it.

Format (little endian), parsed by driver/vfs495_setup.c:
    "VFS495S1"
    u16 n_init,  then n_init  x { u32 len, len bytes }                    plaintext, before the session
    u16 n_setup, then n_setup x { u8 flags, u32 len, len bytes,           encrypted, before each swipe
                                  u16 n_reads, n_reads x u32 size }       ep 0x82 reads after the reply
    flags bit 0: the arming command; the driver writes its image key/IV at ARM_KEY_OFF/ARM_IV_OFF
"""
import json
import os
import struct
import sys

MAGIC = b"VFS495S1"
ARM_LEN = 3033      # the arming command (02, 3033 B) carries the image key (vfs495_native_capture.py)


def pack(init, setup):
    out = bytearray(MAGIC)
    out += struct.pack("<H", len(init))
    for h in init:
        c = bytes.fromhex(h)
        out += struct.pack("<I", len(c)) + c
    out += struct.pack("<H", len(setup))
    for h, reads in setup:
        c = bytes.fromhex(h)
        out += struct.pack("<BI", 1 if len(c) == ARM_LEN else 0, len(c)) + c
        out += struct.pack("<H", len(reads)) + b"".join(struct.pack("<I", n) for n in reads)
    return bytes(out)


def main():
    args = sys.argv[1:]
    if len(args) not in (1, 2):
        sys.exit(__doc__)
    cap = args[0] if len(args) == 2 else os.path.dirname(os.path.abspath(__file__)) + "/../captures"
    init = json.load(open(cap + "/init_cmds.json"))
    setup = json.load(open(cap + "/capture_cmds.json"))
    if sum(len(bytes.fromhex(h)) == ARM_LEN for h, _ in setup) != 1:
        sys.exit("expected exactly one arming command (%d B) in capture_cmds.json" % ARM_LEN)
    data = pack(init, setup)
    with os.fdopen(os.open(args[-1], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
        f.write(data)
    print("%d init + %d setup commands, %d B -> %s" % (len(init), len(setup), len(data), args[-1]))


if __name__ == "__main__":
    main()
