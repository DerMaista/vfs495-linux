/*
 * Validity VFS495: swipe assembly, a C port of tools/vfs495_assemble.py (modelled on HP's
 * IRreconstructImage; validated against HP's own images, see docs/FINDINGS.md 2026-10-10).
 *
 * descrambled lines -> finger span -> drop resting-finger lines (stiction) -> aux->main lag per line
 * (windowed correlation + Viterbi smoothing) -> 8/lag output rows per line, linear interpolation,
 * max 300 rows -> raw values, column percentile stretch, inverted, mirrored.
 * Pure GLib + libm, testable outside libfprint (tests/test_assemble.sh).
 */
#pragma once

#include <glib.h>

#define VFS495_ASM_WIDTH    200      /* output columns (main sensor row) */
#define VFS495_ASM_MAX_ROWS 300

/* lines: n x 264 descrambled pixels. Returns VFS495_ASM_WIDTH x *height pixels (g_free), or NULL
 * when nothing usable was found. */
guint8 *vfs495_assemble (const guint8 *lines,
                         gsize         n,
                         guint        *height);
