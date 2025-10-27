/*
 * PASN initiator fuzzer
 * Copyright (c) 2022, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "../fuzzer-common.h"
#include "common/defs.h"
#include "common/ieee802_11_defs.h"
#include "common/sae.h"
#include "common/wpa_common.h"
#include "crypto/sha384.h"
#include "pasn/pasn_common.h"
#include "utils/common.h"

static int pasn_send_mgmt(void *ctx, const u8 *data, size_t data_len, int noack, unsigned int freq, unsigned int wait) { return 0; }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct pasn_data pasn;
  struct wpa_pasn_params_data pasn_data;
  u8 own_addr[ETH_ALEN], bssid[ETH_ALEN];

  wpa_fuzzer_set_debug_level();

  if (os_program_init())
    return 0;

  os_memset(&pasn, 0, sizeof(pasn));
  pasn.send_mgmt = pasn_send_mgmt;
  hwaddr_aton("02:00:00:00:00:00", own_addr);
  hwaddr_aton("02:00:00:00:03:00", bssid);
  if (wpas_pasn_start(&pasn, own_addr, bssid, bssid, WPA_KEY_MGMT_PASN, WPA_CIPHER_CCMP, 19, 2412, NULL, 0, NULL, 0, NULL) < 0) {
    wpa_printf(MSG_ERROR, "wpas_pasn_start failed");
    goto fail;
  }

  wpa_pasn_auth_rx(&pasn, data, size, &pasn_data);

fail:
  wpa_pasn_reset(&pasn);
  os_program_deinit();

  return 0;
}
