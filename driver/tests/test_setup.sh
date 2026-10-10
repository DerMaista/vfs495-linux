#!/usr/bin/env bash
# Phase 2 check: the C parser reads exactly the commands the Python client uses.
#   driver/tests/test_setup.sh [CAPTURES_DIR]      (needs: cc, pkg-config glib-2.0, python3)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
cap=${1:-$here/../../captures}
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
python3 "$here/../../tools/make_setup_bin.py" "$cap" "$tmp/setup.bin" >/dev/null
cc -Wall -Werror -o "$tmp/test_setup" "$here/test_setup.c" "$here/../vfs495_setup.c" $(pkg-config --cflags --libs glib-2.0)
"$tmp/test_setup" "$tmp/setup.bin" --corrupt > "$tmp/c.txt"
python3 - "$cap" > "$tmp/py.txt" <<'PY'
import hashlib, json, sys
cap = sys.argv[1]
for i, h in enumerate(json.load(open(cap + "/init_cmds.json"))):
    c = bytes.fromhex(h); print("init", i, len(c), hashlib.sha256(c).hexdigest())
for i, (h, reads) in enumerate(json.load(open(cap + "/capture_cmds.json"))):
    c = bytes.fromhex(h)
    print("setup", i, int(len(c) == 3033), len(c), hashlib.sha256(c).hexdigest(), *reads)
PY
diff -u "$tmp/py.txt" "$tmp/c.txt"
echo "OK: C parser == Python client ($(grep -c ^init "$tmp/c.txt") init, $(grep -c ^setup "$tmp/c.txt") setup commands)"
