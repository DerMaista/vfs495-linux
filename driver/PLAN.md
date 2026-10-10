# Plan: native libfprint driver for the VFS495 (no HP binary at runtime)

Port the working Python client (`tools/ssl_session.py`, `tools/vfs495_native_capture.py`) into the
scaffold `driver/vfs495.c`, and let libfprint's existing `fpi_assemble_lines()` do the image assembly.
Background for every step: `docs/FINDINGS.md` and `docs/SSL_PROTOCOL.md`.

## Starting point

**Already in the scaffold:** libfprint device boilerplate, a capture state machine with five empty TODO
states, line descrambling (`vfs495_descramble.inc`), and a call to `fpi_assemble_lines()`.

**Wrong in the scaffold:**
- Assembly configuration: `get_deviation` compares the same columns of two lines, which does not measure
  finger speed. Rows only keep the 200 main columns, so the aux row (columns 200–263) is thrown away.
- Line splitting: a placeholder magic-byte splitter from before we knew the swipe stream is encrypted.
- Status: the README still calls the SSL session the main blocker. It is solved (wrong RSA key, see
  FINDINGS 2026-10-09).

**Available to reuse:**
- The Python client, verified on hardware: session, setup with a random image key, finger poll,
  encrypted swipe stream, decryption.
- libfprint's optional OpenSSL >= 3.0 helper (used by the `uru4000` driver) for AES-256-CBC, SHA-1, MD5
  and RSA.
- `fpi_assemble_lines()`, which already does what HP's `IRreconstructImage` does for vertical height:
  per-line lag search, median filter, fixed-rate interpolation, height cap. The `vfs5011` driver uses it
  for the same two-row sensor design.

## Phase 1: build setup
- Build libfprint 1.94.x with the driver in a Nix shell (meson, ninja, OpenSSL).
- Register `vfs495` in the driver list with `helper: ['openssl']`.
- Test: the driver loads and lists `138a:003f`.

## Phase 2: setup data instead of embedded blobs
- HP's patches and setup commands cannot be shipped. The driver reads one local file, for example
  `/var/lib/vfs495/setup.bin`.
- Extend `runtime/trace_to_init.py` to write that file from the one-time HP trace (init commands plus the
  decrypted setup commands with their ep 0x82 read sizes).
- Test: the C parser loads the same commands the Python client uses.

## Phase 3: init and session (port of `ssl_session.py`)
- Async USB transfers (`fpi_usb_transfer`) on endpoints 0x01, 0x81 and 0x82.
- Init sequence: GetVersion; send `1a` UnloadPatch if byte 17 shows patches loaded; the two patch uploads
  with ~30 ms pauses; flash reads of exactly the requested size (128 and 4096 bytes, u32 at command
  offset 5).
- RSA session key from flash storage id 10 (`EAT"` table from byte 13: `ff <id> <u32 addr> <u32 size>`).
- SSLv3 handshake with the Validity quirks:
  - the key-exchange ciphertext uses the little-endian modulus, big-endian message and output;
  - the Finished labels `CLNT` / `SRVR` are hashed as little-endian integers;
  - record MACs leave out the length field;
  - the sensor's Finished covers the same messages as ours (our Finished is not hashed in).
- Encrypted commands with replies up to 16 KiB (the sensor ends replies with a short packet).
- `close_notify` (encrypted alert `01 00`) on deactivate and close.
- Stale session: if the first reply is an alert, report a retryable error; the sensor resets itself and
  re-enumerates.
- Test: open, encrypted GetVersion, close, three times in a row without re-enumeration (matches the
  Python client).

## Phase 4: capture
- Setup commands with a fresh random image key and IV at offsets 2927 and 2959 of the 3033 B arming
  command.
- Finger detection: poll `17` (GetFingerState) every ~50 ms; byte 2 bit 1 = finger. Report finger-on with
  `fpi_image_device_report_finger_status()`. This gives fprintd's `finger-present` natively (Tabularium's
  dial), without the bridge workaround.
- Stream: 16 KiB reads from ep 0x82, decrypted incrementally as one AES-256-CBC stream, split into 272 B
  frames (`01 fe`, byte 2 = line sequence counter, so gaps can be detected; 8 B header + 264 pixels).
- Swipe end: read timeout of ~150 ms (the sensor stops streaming ~0.4 s after the finger leaves), then
  `04` AbortFingerprint, drain ep 0x82, consume the reply to keep the SSL state in sync. Report finger-off.
- Test: frame count and sequence-gap count match the Python tool for comparable swipes.

## Phase 5: assembly via libfprint's helper
- Rows keep all 264 columns, minus a per-column baseline taken from the empty-sensor calibration scans
  the setup commands already produce.
- `get_deviation(earlier, later)`: compare the earlier line's aux columns 200–263 with the later line's
  main columns ~70–133. The minimum over the search window is the aux-to-main lag (the speedometer).
- `get_pixel(x)`: main columns mirrored (199 − x), like HP's output.
- Parameters (starting values, tune in phase 6):
  - `max_search_offset` ≈ 220 (measured lags go up to ~200 lines);
  - `resolution` ≈ 4 (row distance ~4.3 px);
  - `median_filter_size` 25 (as vfs5011 / vfs0050);
  - `max_height` ≈ 300–400 (HP caps at 300).
- Quality gate: retry the scan when it is too short or the lags are erratic (`FP_DEVICE_RETRY_TOO_SHORT`
  and similar).

## Phase 6: measuring
- libfprint's `examples/img-capture` for single images; `vfs495-match` and the quality test for 5–10
  swipes scored against each other, plus a different finger as an impostor check.
- Target: genuine pairs consistently >= 40, impostors clearly below.
- Tune `resolution`, `max_search_offset` and the deviation measure (sum of absolute differences vs.
  correlation).

## Phase 7: integration
- NixOS overlay that patches libfprint with the driver; module option to choose `native` or `bridge`
  (the current gdb bridge stays as fallback). Drop `FP_VIRTUAL_IMAGE` when native.
- New enrollment with native captures (HP-made templates will not match).
- Docs: update `driver/README.md`, and SETUP for producing the setup file.

## Risks and open points
- Out-of-tree only: libfprint upstream will not take a driver that needs HP's traced blobs, so this stays
  a patch.
- `fpi_assemble_lines()` does not correct sideways drift. Hopefully acceptable; otherwise a later step.
- The aux row is only 64 pixels wide, so the lag search may be noisier than HP's. Phase 6 will show it.
- Effort: phases 1–4 are mostly mechanical porting of tested Python. The real unknown is matching
  quality in phase 6.

## Status

**Phase 1 — done (2026-10-10).** `driver/default.nix` adds the driver to nixpkgs' libfprint (1.94.100):
copies the files, registers `vfs495` with `helper: ['openssl']`, drops `138a:003f` from libfprint's
"known unsupported" list and patches the committed `data/autosuspend.hwdb` (otherwise the `udev-hwdb` test
fails). Builds without warnings, libfprint's test suite passes, and the patched library enumerates the
sensor as `vfs495 / Validity VFS495`. Dev build:
`nix build --impure --expr '(builtins.getFlake "nixpkgs").legacyPackages.x86_64-linux.callPackage ./driver { }'`

**Phase 2 — done (2026-10-10), with one gap.** `tools/make_setup_bin.py` packs `captures/init_cmds.json` +
`capture_cmds.json` into `/var/lib/vfs495/setup.bin` (format in the script). `driver/vfs495_setup.c` parses
it (pure GLib); the driver loads it in `dev_open` (`VFS495_SETUP` overrides the path) and fails the open
with a clear message when it is missing or invalid. `driver/tests/test_setup.sh`: the C parser yields the
same 8 init + 24 setup commands (sha256 + ep 0x82 read sizes) as the Python client, and every truncation
plus a bad magic is rejected.
Gap: no repo tool produces `capture_cmds.json` from a fresh HP trace yet (it came from scratch gdb scripts:
key-block dump at `scsSSLRsaPublicEncrypt` + usblog trace + record decryption). Needed for any second
device; `trace_to_init.py` only covers the init part.

**Phase 3 — done (2026-10-10).** `driver/vfs495_ssl.c`: the session protocol (PRF, Validity RSA byte order,
Finished, record MAC/encryption, flash storage table) on OpenSSL, no USB. `tests/test_ssl.sh` runs
`tools/ssl_session.py` against a simulated sensor with fixed randomness and checks the C layer byte for byte
(ClientHello, key exchange flight, sensor Finished, encrypted GetVersion + reply, close_notify, tampered
record rejected). `vfs495.c`: `dev_open` runs the init sequence (30 ms pauses, `1a` unload when patches are
still loaded, exact-size flash reads), takes the RSA key from storage id 10, does the handshake and an
encrypted GetVersion; `dev_close` sends close_notify. Hardware: 3x open/session/GetVersion/close through
libfprint, sensor confirmed every close, USB address unchanged (no re-enumeration), ~0.6 s per open.

**Phase 4 — done (2026-10-10).** Capture loop in `vfs495.c` (one SSM run per swipe, restarted until
deactivation): setup commands with a fresh random image key/IV in the arming command, `17` poll every 50 ms
(finger-on reported to libfprint), ep 0x82 stream decrypted incrementally (one EVP AES-256-CBC context),
272 B frames split, sequence gaps / bad frames counted, end on 150 ms read timeout / 4 s / quiet rule, then
`04` abort, drain, reply consumed (SSL sequence stays in sync), finger-off. Deactivation while waiting for a
finger disarms with `04`. `VFS495_RAW=FILE.npy` dumps the raw lines. Hardware: 3 swipes in one open
session, ~8–12k lines each; their raw lines assembled by `tools/vfs495_assemble.py` give clean prints, so
capture and decryption are correct. The interim `fpi_assemble_lines()` output (resolution 8, search 220)
is unusable streaks, as predicted below: it stretches the resting part before the swipe.

**Phase 5 — done (2026-10-10), as a C port instead of `fpi_assemble_lines()`.** `driver/vfs495_assemble.c`
ports `tools/vfs495_assemble.py` (scipy/numpy semantics reproduced: gaussian truncate 4 + reflect borders,
`np.convolve 'same'`, `np.interp`, linear percentiles, numpy argmax tie-breaking in the Viterbi).
`tests/test_assemble.sh RAW.npy...`: pixel-identical to the Python on 3 recorded driver swipes (max diff 0),
1.1–1.9 s per swipe (-O2). The driver hands the 200 x <=300 image to libfprint; prints under 80 rows are
retried. Also removed the scaffold's `bz3_threshold = 20` (half libfprint's default 40: too permissive).

**Phase 6 — started.** First full-driver run (libfprint only, no HP, no Python): 6 swipes, one session,
~7–8 s from prompt to image (about 3 s streaming + ~1 s assembly + setup); all six are prints, one-to-one
scores mean 27.7, 1/15 >= 40 (best 71). The Python path on an earlier live set: mean 39.4, 7/15; same
algorithm, so this is swipe-to-swipe variance, the open quality problem. Every swipe shows exactly 1
sequence gap + 1 bad frame: probably one non-image block at the stream start; to check. Next: real
fprintd enroll (5 samples) + verify with this libfprint, which is the measure that matters.

**Notes that led to the phase 5 decision (from the offline/live assembly tests, FINDINGS 2026-10-10):**
- `resolution` must be ~8, not ~4: the lag is measured in lines (50–170), and HP's rule is 8 lines of lag =
  1 output row (7 and 9 both scored worse).
- `fpi_assemble_lines()` searches each line pair independently (one line vs. one line, no windowing) and
  only median-filters the result. In our tests a per-line search slid into a spurious lag minimum, and a
  windowed correlation with a smoothness cost (Viterbi) was what worked. It also always advances at least
  one row per line pair, so a resting finger (stiction) gets stretched into streaks — the exact failure the
  live test showed. Expect to need either a custom `get_deviation` over a window plus pre-dropping resting
  lines, or a C port of `tools/vfs495_assemble.py` (~150 lines) instead of `fpi_assemble_lines()`.
- Use raw pixel values, inverted polarity, column percentile stretch (1/94), mirror L-R, no vertical flip
  (note `fpi_assemble_lines` sets `FPI_IMAGE_V_FLIPPED`).
