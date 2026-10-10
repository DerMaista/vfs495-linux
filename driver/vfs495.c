/*
 * Validity VFS495 (138a:003f) fingerprint reader driver for libfprint
 *
 * Copyright (C) 2026  (reverse-engineered from HP's Validity 4.5-136 Linux driver)
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License, version 2.1 or later.
 *
 * STATUS (see PLAN.md): open/close run the sensor's init sequence and SSLv3 session (port of
 * tools/ssl_session.py, verified byte-exact offline by tests/test_ssl.sh). Capture (phase 4) and
 * assembly (phase 5) are still placeholders. Modeled on the vfs5011/vfs301 sibling drivers.
 */

#define FP_COMPONENT "vfs495"

#include "drivers_api.h"
#include "vfs495_proto.h"
#include "vfs495_setup.h"
#include "vfs495_ssl.h"

#include <openssl/rand.h>

struct _FpDeviceVfs495
{
  FpImageDevice parent;

  Vfs495Setup  *setup;            /* init/setup commands (VFS495_SETUP_PATH) */
  Vfs495Ssl     ssl;
  Vfs495Handshake hs;
  gboolean      session_open;
  guint         init_idx;         /* next init command */
  GBytes       *flash;            /* the 4 KiB flash block (storage table) */
  GByteArray   *reply;            /* last reply read by recv () */

  guint8       *capture_buf;      /* raw ep2 DLI bytes                 */
  gsize         capture_len;
  GSList       *rows;             /* captured descrambled lines (g_malloc) */
  gint          lines_recorded;
  gboolean      deactivating;
  gboolean      loop_running;
};
G_DECLARE_FINAL_TYPE (FpDeviceVfs495, fpi_device_vfs495, FPI, DEVICE_VFS495,
                      FpImageDevice)
G_DEFINE_TYPE (FpDeviceVfs495, fpi_device_vfs495, FP_TYPE_IMAGE_DEVICE)

#include "vfs495_descramble.inc"

/* ---------------------------------------------------------------------------
 * DLI line decode (UnpackLineRT): input = one framed line (8-byte header +
 * payload); output = VFS495_LINE_WIDTH descrambled 8-bit pixels.
 * Returns TRUE on success. Only the 8-bit-direct mode (our sensor) is wired up;
 * 4-bit / bit-packed modes are stubbed for other Falcon variants.
 * ------------------------------------------------------------------------- */
static gboolean
vfs495_decode_line (const guint8 *line, gsize len, guint8 *out /* [LINE_WIDTH] */)
{
  guint mode;

  if (len < VFS495_LINE_HDR + VFS495_LINE_WIDTH)
    return FALSE;

  mode = line[6] & 0x0f;
  if (mode != VFS495_DECODE_8BIT)
    {
      /* TODO: 4-bit and variable-bitlength modes (see UnpackLineRT). */
      fp_dbg ("vfs495: unsupported decode mode %u", mode);
      return FALSE;
    }

  /* 8-bit direct: out[descramble[i]] = payload[i] */
  const guint8 *px = line + VFS495_LINE_HDR;
  for (guint i = 0; i < VFS495_LINE_WIDTH; i++)
    out[vfs495_descramble[i]] = px[i];

  return TRUE;
}

/* Assembly pulls the usable main-image columns (0..IMAGE_WIDTH-1). */
static unsigned char
vfs495_get_pixel (struct fpi_line_asmbl_ctx *ctx, GSList *row, unsigned x)
{
  (void) ctx;
  return ((const guint8 *) row->data)[x];
}

static int
vfs495_get_deviation (struct fpi_line_asmbl_ctx *ctx, GSList *a, GSList *b)
{
  /* Mean absolute difference between two lines -> movement proxy. */
  const guint8 *pa = a->data, *pb = b->data;
  int sum = 0;

  for (unsigned x = 0; x < ctx->line_width; x++)
    sum += abs ((int) pa[x] - (int) pb[x]);
  return sum / (int) ctx->line_width;
}

static struct fpi_line_asmbl_ctx assembling_ctx = {
  .line_width         = VFS495_IMAGE_WIDTH,
  .max_height         = 2000,
  .resolution         = 10,
  .median_filter_size = 25,
  .max_search_offset  = 30,
  .get_deviation      = vfs495_get_deviation,
  .get_pixel          = vfs495_get_pixel,
};

/* ---------------------------------------------------------------------------
 * Capture SSM
 * ------------------------------------------------------------------------- */
enum activate_states {
  ACTIVATE_START,
  ACTIVATE_AWAIT_FINGER,   /* poll finger state / interrupt ep 0x83          */
  ACTIVATE_CAPTURE,        /* read DLI stream from ep 0x82                   */
  ACTIVATE_PROCESS,        /* decode + descramble + assemble                 */
  ACTIVATE_NUM_STATES,
};

static void
vfs495_submit_image (FpiSsm *ssm, FpDeviceVfs495 *self, FpImageDevice *dev)
{
  FpImage *img;

  if (self->lines_recorded < VFS495_IMAGE_WIDTH)
    {
      fpi_image_device_retry_scan (dev, FP_DEVICE_RETRY_TOO_SHORT);
      return;
    }

  self->rows = g_slist_reverse (self->rows);
  img = fpi_assemble_lines (&assembling_ctx, self->rows, self->lines_recorded);
  g_slist_free_full (g_steal_pointer (&self->rows), g_free);
  self->lines_recorded = 0;

  fpi_image_device_image_captured (dev, img);
}

/*
 * Split the raw ep2 DLI buffer into lines, decode+descramble each, and keep the
 * usable main-image columns. NOTE: line framing here is the simple magic-scan
 * placeholder; port irDliRTFalconData's stateful accumulator for robustness
 * (ridge data legitimately contains the 0x01/0xfe marker bytes).
 */
static void
vfs495_process_capture (FpDeviceVfs495 *self)
{
  const guint8 *b = self->capture_buf;
  gsize n = self->capture_len, i = 0;
  guint8 dec[VFS495_LINE_WIDTH];

  while (i + VFS495_LINE_HDR + VFS495_LINE_WIDTH <= n)
    {
      if (b[i] == 0x01 && (b[i + 1] == 0x01 || b[i + 1] == 0xfe) &&
          b[i + 3] == 0x00 && b[i + 7] == 0x00 &&
          vfs495_decode_line (b + i, n - i, dec))
        {
          guint8 *keep = g_malloc (VFS495_IMAGE_WIDTH);
          memcpy (keep, dec, VFS495_IMAGE_WIDTH); /* main-image columns */
          self->rows = g_slist_prepend (self->rows, keep);
          self->lines_recorded++;
          i += VFS495_LINE_HDR + VFS495_LINE_WIDTH;
        }
      else
        {
          i++;
        }
    }
}

static void
activate_run_state (FpiSsm *ssm, FpDevice *_dev)
{
  FpImageDevice *dev = FP_IMAGE_DEVICE (_dev);
  FpDeviceVfs495 *self = FPI_DEVICE_VFS495 (_dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case ACTIVATE_START:
      /* the session is already open (dev_open); phase 4: setup commands with a fresh image key */
      fpi_image_device_activate_complete (dev, NULL);
      fpi_ssm_next_state (ssm);
      break;

    case ACTIVATE_AWAIT_FINGER:
      /* TODO: wait on interrupt ep 0x83 (finger event) or poll GET_FINGER_STATE. */
      fpi_ssm_next_state (ssm);
      break;

    case ACTIVATE_CAPTURE:
      /* TODO: issue GET_FINGERPRINT and read the DLI stream from ep 0x82 into
       * self->capture_buf / capture_len via fpi_usb_transfer. */
      fpi_ssm_next_state (ssm);
      break;

    case ACTIVATE_PROCESS:
      if (self->capture_buf && self->capture_len)
        vfs495_process_capture (self);
      vfs495_submit_image (ssm, self, dev);
      fpi_ssm_mark_completed (ssm);
      break;
    }
}

static void
activate_complete (FpiSsm *ssm, FpDevice *_dev, GError *error)
{
  FpImageDevice *dev = FP_IMAGE_DEVICE (_dev);
  FpDeviceVfs495 *self = FPI_DEVICE_VFS495 (_dev);

  self->loop_running = FALSE;
  g_clear_pointer (&self->capture_buf, g_free);
  self->capture_len = 0;

  if (self->deactivating)
    fpi_image_device_deactivate_complete (dev, error);
  else if (error)
    fpi_image_device_session_error (dev, error);
}

/* ---------------------------------------------------------------------------
 * USB helpers: every exchange is one SSM state that sends, one that reads into
 * self->reply, then a state that looks at the reply.
 * ------------------------------------------------------------------------- */
#define CMD_TIMEOUT   3000
#define INIT_PAUSE    30      /* ms between init commands: back to back, the sensor resets */
#define REPLY_SMALL   0x400   /* init + handshake replies */
#define REPLY_LARGE   0x4000  /* encrypted command replies (the sensor ends them with a short packet) */

static void
send_buf (FpiSsm *ssm, FpDevice *dev, const guint8 *data, gsize len)
{
  FpiUsbTransfer *t = fpi_usb_transfer_new (dev);

  t->ssm = ssm;
  t->short_is_error = TRUE;
  fpi_usb_transfer_fill_bulk_full (t, VFS495_EP_CMD_OUT, g_memdup2 (data, len), len, g_free);
  fpi_usb_transfer_submit (t, CMD_TIMEOUT, NULL, fpi_ssm_usb_transfer_cb, NULL);
}

static void
send_array (FpiSsm *ssm, FpDevice *dev, GByteArray *data)
{
  send_buf (ssm, dev, data->data, data->len);
  g_byte_array_unref (data);
}

static void
recv_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer user_data, GError *error)
{
  FpDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);

  if (error)
    {
      fpi_ssm_mark_failed (t->ssm, error);
      return;
    }
  g_clear_pointer (&self->reply, g_byte_array_unref);
  self->reply = g_byte_array_sized_new (t->actual_length);
  g_byte_array_append (self->reply, t->buffer, t->actual_length);
  fpi_ssm_next_state (t->ssm);
}

static void
recv_buf (FpiSsm *ssm, FpDevice *dev, guint8 ep, gsize len, guint timeout)
{
  FpiUsbTransfer *t = fpi_usb_transfer_new (dev);

  t->ssm = ssm;
  fpi_usb_transfer_fill_bulk (t, ep, len);
  fpi_usb_transfer_submit (t, timeout, NULL, recv_cb, NULL);
}

static void
random_bytes (guint8 *out, gsize len, gboolean nonzero)
{
  RAND_bytes (out, len);
  for (gsize i = 0; nonzero && i < len; i++)
    while (out[i] == 0)
      RAND_bytes (out + i, 1);
}

/* ---------------------------------------------------------------------------
 * Open: init sequence (plaintext), then the SSLv3 session. tools/ssl_session.py
 * ------------------------------------------------------------------------- */
enum open_states {
  OPEN_INIT_PAUSE,
  OPEN_INIT_SEND,
  OPEN_INIT_RECV,
  OPEN_INIT_CHECK,
  OPEN_UNLOAD_PAUSE,      /* patches still loaded: 1a UnloadPatch, like HP */
  OPEN_UNLOAD_SEND,
  OPEN_UNLOAD_RECV,
  OPEN_UNLOAD_DONE,
  OPEN_FLASH_RECV,        /* 1f SPI flash read: the data follows on ep 0x82 */
  OPEN_FLASH_DONE,
  OPEN_HELLO_SEND,
  OPEN_HELLO_RECV,
  OPEN_FLIGHT_SEND,
  OPEN_FLIGHT_RECV,
  OPEN_FLIGHT_CHECK,
  OPEN_VERSION_SEND,
  OPEN_VERSION_RECV,
  OPEN_VERSION_CHECK,
  OPEN_NUM_STATES,
};

static GBytes *
init_cmd (FpDeviceVfs495 *self)
{
  return g_ptr_array_index (self->setup->init, self->init_idx);
}

static void
open_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);
  g_autoptr(GError) error = NULL;
  const guint8 *cmd;
  gsize cmdlen;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case OPEN_INIT_PAUSE:
      if (self->init_idx >= self->setup->init->len)
        fpi_ssm_jump_to_state (ssm, OPEN_HELLO_SEND);
      else
        fpi_ssm_next_state_delayed (ssm, INIT_PAUSE);
      break;

    case OPEN_INIT_SEND:
      cmd = g_bytes_get_data (init_cmd (self), &cmdlen);
      send_buf (ssm, dev, cmd, cmdlen);
      break;

    case OPEN_INIT_RECV:
      recv_buf (ssm, dev, VFS495_EP_CMD_IN, REPLY_SMALL, CMD_TIMEOUT);
      break;

    case OPEN_INIT_CHECK:
      cmd = g_bytes_get_data (init_cmd (self), &cmdlen);
      if (self->reply->len >= 1 && self->reply->data[0] == VFS495_REC_ALERT)
        {
          /* still in a session from an earlier process: the sensor resets itself and re-enumerates */
          fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                              "sensor held a stale session and is resetting; try again"));
          return;
        }
      if (cmd[0] == VFS495_CMD_GET_VERSION && self->reply->len > 17 && self->reply->data[17] && !self->flash)
        fpi_ssm_jump_to_state (ssm, OPEN_UNLOAD_PAUSE);
      else if (cmd[0] == VFS495_CMD_SPI_BULK_READ && cmdlen >= 9)
        fpi_ssm_jump_to_state (ssm, OPEN_FLASH_RECV);
      else
        {
          self->init_idx++;
          fpi_ssm_jump_to_state (ssm, OPEN_INIT_PAUSE);
        }
      break;

    case OPEN_UNLOAD_PAUSE:
      fp_dbg ("patches still loaded: unloading first");
      fpi_ssm_next_state_delayed (ssm, INIT_PAUSE);
      break;

    case OPEN_UNLOAD_SEND:
      send_buf (ssm, dev, (const guint8 *) "\x1a", 1);
      break;

    case OPEN_UNLOAD_RECV:
      recv_buf (ssm, dev, VFS495_EP_CMD_IN, REPLY_SMALL, CMD_TIMEOUT);
      break;

    case OPEN_UNLOAD_DONE:
      self->init_idx++;
      fpi_ssm_jump_to_state (ssm, OPEN_INIT_PAUSE);
      break;

    case OPEN_FLASH_RECV:
      /* read exactly the requested size (u32 at offset 5): the sensor sends full packets, no short one */
      cmd = g_bytes_get_data (init_cmd (self), &cmdlen);
      recv_buf (ssm, dev, VFS495_EP_DATA_IN, cmd[5] | (cmd[6] << 8) | (cmd[7] << 16) | ((guint32) cmd[8] << 24), 1000);
      break;

    case OPEN_FLASH_DONE:
      if (self->reply->len == 0x1000)
        {
          g_clear_pointer (&self->flash, g_bytes_unref);
          self->flash = g_bytes_new (self->reply->data, self->reply->len);
        }
      self->init_idx++;
      fpi_ssm_jump_to_state (ssm, OPEN_INIT_PAUSE);
      break;

    case OPEN_HELLO_SEND:
      {
        guint8 client_random[VFS495_SSL_RANDOM_LEN], premaster[VFS495_SSL_PREMASTER_LEN];

        if (!self->flash)
          {
            fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                                "init read no flash block (setup file incomplete?)"));
            return;
          }
        random_bytes (client_random, sizeof (client_random), FALSE);
        random_bytes (premaster, sizeof (premaster), FALSE);
        vfs495_handshake_clear (&self->hs);
        vfs495_handshake_init (&self->hs, client_random, premaster);
        send_array (ssm, dev, vfs495_handshake_hello (&self->hs));
      }
      break;

    case OPEN_HELLO_RECV:
      recv_buf (ssm, dev, VFS495_EP_CMD_IN, REPLY_SMALL, CMD_TIMEOUT);
      break;

    case OPEN_FLIGHT_SEND:
      {
        g_autoptr(GBytes) modulus = vfs495_flash_storage (g_bytes_get_data (self->flash, NULL),
                                                          g_bytes_get_size (self->flash), 10);
        guint8 pad[VFS495_RSA_LEN - 3 - VFS495_SSL_PREMASTER_LEN];
        GByteArray *flight;

        if (!modulus)
          {
            fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                                "RSA key (storage id 10) not found in sensor flash"));
            return;
          }
        random_bytes (pad, sizeof (pad), TRUE);
        flight = vfs495_handshake_flight (&self->hs, &self->ssl, self->reply->data, self->reply->len,
                                          g_bytes_get_data (modulus, NULL), g_bytes_get_size (modulus),
                                          pad, &error);
        if (!flight)
          {
            fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "%s", error->message));
            return;
          }
        send_array (ssm, dev, flight);
      }
      break;

    case OPEN_FLIGHT_RECV:
      recv_buf (ssm, dev, VFS495_EP_CMD_IN, REPLY_SMALL, CMD_TIMEOUT);
      break;

    case OPEN_FLIGHT_CHECK:
      if (!vfs495_handshake_verify (&self->hs, &self->ssl, self->reply->data, self->reply->len, &error))
        {
          fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "handshake: %s", error->message));
          return;
        }
      vfs495_handshake_clear (&self->hs);
      self->session_open = TRUE;
      fp_dbg ("secure session open, sensor Finished verified");
      fpi_ssm_next_state (ssm);
      break;

    case OPEN_VERSION_SEND:
      send_array (ssm, dev, vfs495_ssl_encrypt (&self->ssl, VFS495_REC_APPDATA, (const guint8 *) "\x01", 1));
      break;

    case OPEN_VERSION_RECV:
      recv_buf (ssm, dev, VFS495_EP_CMD_IN, REPLY_LARGE, CMD_TIMEOUT);
      break;

    case OPEN_VERSION_CHECK:
      {
        g_autoptr(GByteArray) plain = vfs495_ssl_decrypt (&self->ssl, self->reply->data, self->reply->len,
                                                          NULL, &error);
        if (!plain || plain->len < 2 || plain->data[0] || plain->data[1])
          {
            fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "encrypted GetVersion failed%s%s",
                                                                error ? ": " : "", error ? error->message : ""));
            return;
          }
        fp_dbg ("encrypted GetVersion ok (%u B reply)", plain->len);
        fpi_ssm_mark_completed (ssm);
      }
      break;
    }
}

static void
release_usb (FpDeviceVfs495 *self)
{
  g_usb_device_release_interface (fpi_device_get_usb_device (FP_DEVICE (self)), 0, 0, NULL);
  g_clear_pointer (&self->setup, vfs495_setup_free);
  g_clear_pointer (&self->flash, g_bytes_unref);
  g_clear_pointer (&self->reply, g_byte_array_unref);
  vfs495_handshake_clear (&self->hs);
  self->session_open = FALSE;
}

static void
open_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);

  if (error)
    release_usb (self);
  fpi_image_device_open_complete (FP_IMAGE_DEVICE (dev), error);
}

static void
dev_open (FpImageDevice *dev)
{
  GError *error = NULL;
  FpDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);
  GUsbDevice *usb = fpi_device_get_usb_device (FP_DEVICE (dev));
  const char *path = g_getenv ("VFS495_SETUP") ?: VFS495_SETUP_PATH;

  /* HP's per-device patches + setup commands, recorded once (tools/make_setup_bin.py) */
  self->setup = vfs495_setup_load (path, &error);
  if (!self->setup)
    {
      g_prefix_error (&error, "%s: ", path);
      fpi_image_device_open_complete (dev, error);
      return;
    }
  fp_dbg ("setup: %u init + %u setup commands from %s",
          self->setup->init->len, self->setup->setup->len, path);

  if (!g_usb_device_claim_interface (usb, 0, 0, &error))
    {
      g_clear_pointer (&self->setup, vfs495_setup_free);
      fpi_image_device_open_complete (dev, error);
      return;
    }

  self->init_idx = 0;
  fpi_ssm_start (fpi_ssm_new (FP_DEVICE (dev), open_run_state, OPEN_NUM_STATES), open_complete);
}

/* ---------------------------------------------------------------------------
 * Close: encrypted close_notify (01 00), like HP on exit. Without it the sensor keeps the session
 * and resets itself on the next open (a re-enumeration). Errors here are not fatal.
 * ------------------------------------------------------------------------- */
enum close_states {
  CLOSE_SEND,
  CLOSE_RECV,
  CLOSE_CHECK,
  CLOSE_NUM_STATES,
};

static void
close_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case CLOSE_SEND:
      if (!self->session_open)
        {
          fpi_ssm_mark_completed (ssm);
          return;
        }
      send_array (ssm, dev, vfs495_ssl_encrypt (&self->ssl, VFS495_REC_ALERT, (const guint8 *) "\x01\x00", 2));
      break;

    case CLOSE_RECV:
      recv_buf (ssm, dev, VFS495_EP_CMD_IN, REPLY_SMALL, 1000);
      break;

    case CLOSE_CHECK:
      {
        g_autoptr(GByteArray) plain = NULL;
        guint8 type = 0;

        plain = vfs495_ssl_decrypt (&self->ssl, self->reply->data, self->reply->len, &type, NULL);
        fp_dbg ("session closed: %s", plain && type == VFS495_REC_ALERT ? "sensor confirmed" : "NOT confirmed");
        fpi_ssm_mark_completed (ssm);
      }
      break;
    }
}

static void
close_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  if (error)
    fp_dbg ("close_notify failed: %s", error->message);
  g_clear_error (&error);
  release_usb (FPI_DEVICE_VFS495 (dev));
  fpi_image_device_close_complete (FP_IMAGE_DEVICE (dev), NULL);
}

static void
dev_close (FpImageDevice *dev)
{
  FpDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);

  g_clear_pointer (&self->capture_buf, g_free);
  g_slist_free_full (g_steal_pointer (&self->rows), g_free);
  fpi_ssm_start (fpi_ssm_new (FP_DEVICE (dev), close_run_state, CLOSE_NUM_STATES), close_complete);
}

static void
dev_activate (FpImageDevice *dev)
{
  FpDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);
  FpiSsm *ssm;

  self->deactivating = FALSE;
  self->loop_running = TRUE;
  ssm = fpi_ssm_new (FP_DEVICE (dev), activate_run_state, ACTIVATE_NUM_STATES);
  fpi_ssm_start (ssm, activate_complete);
}

static void
dev_deactivate (FpImageDevice *dev)
{
  FpDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);

  if (self->loop_running)
    self->deactivating = TRUE;
  else
    fpi_image_device_deactivate_complete (dev, NULL);
}

static const FpIdEntry id_table[] = {
  { .vid = VFS495_VID, .pid = VFS495_PID, },
  { .vid = 0, .pid = 0, },
};

static void
fpi_device_vfs495_init (FpDeviceVfs495 *self)
{
}

static void
fpi_device_vfs495_class_init (FpDeviceVfs495Class *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);
  FpImageDeviceClass *img_class = FP_IMAGE_DEVICE_CLASS (klass);

  dev_class->id = "vfs495";
  dev_class->full_name = "Validity VFS495";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_SWIPE;

  img_class->img_open = dev_open;
  img_class->img_close = dev_close;
  img_class->activate = dev_activate;
  img_class->deactivate = dev_deactivate;

  img_class->bz3_threshold = 20;
  img_class->img_width = VFS495_IMAGE_WIDTH;
  img_class->img_height = -1;
}
