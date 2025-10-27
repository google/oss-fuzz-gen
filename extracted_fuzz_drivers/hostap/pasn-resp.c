/*
 * PASN responder fuzzer
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
#include "crypto/crypto.h"
#include "crypto/sha384.h"
#include "pasn/pasn_common.h"
#include "utils/common.h"
#include "utils/eloop.h"

struct eapol_state_machine;

struct rsn_pmksa_cache_entry *pmksa_cache_auth_add(struct rsn_pmksa_cache *pmksa, const u8 *pmk, size_t pmk_len, const u8 *pmkid, const u8 *kck, size_t kck_len, const u8 *aa, const u8 *spa, int session_timeout, struct eapol_state_machine *eapol, int akmp) { return NULL; }

struct rsn_pmksa_cache_entry *pmksa_cache_auth_get(struct rsn_pmksa_cache *pmksa, const u8 *spa, const u8 *pmkid) { return NULL; }

static int pasn_send_mgmt(void *ctx, const u8 *data, size_t data_len, int noack, unsigned int freq, unsigned int wait) { return 0; }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct pasn_data pasn;
  u8 own_addr[ETH_ALEN], bssid[ETH_ALEN];

  wpa_fuzzer_set_debug_level();

  if (os_program_init())
    return 0;

  if (eloop_init()) {
    wpa_printf(MSG_ERROR, "Failed to initialize event loop");
    return 0;
  }

  os_memset(&pasn, 0, sizeof(pasn));
  pasn.send_mgmt = pasn_send_mgmt;
  hwaddr_aton("02:00:00:00:03:00", own_addr);
  hwaddr_aton("02:00:00:00:00:00", bssid);
  os_memcpy(pasn.own_addr, own_addr, ETH_ALEN);
  os_memcpy(pasn.bssid, bssid, ETH_ALEN);
  pasn.wpa_key_mgmt = WPA_KEY_MGMT_PASN;
  pasn.rsn_pairwise = WPA_CIPHER_CCMP;

  wpa_printf(MSG_DEBUG, "TESTING: Try to parse as PASN Auth 1");
  if (handle_auth_pasn_1(&pasn, own_addr, bssid, (const struct ieee80211_mgmt *)data, size))
    wpa_printf(MSG_ERROR, "handle_auth_pasn_1 failed");

  wpa_printf(MSG_DEBUG, "TESTING: Try to parse as PASN Auth 3");
  if (handle_auth_pasn_3(&pasn, own_addr, bssid, (const struct ieee80211_mgmt *)data, size))
    wpa_printf(MSG_ERROR, "handle_auth_pasn_3 failed");

  if (pasn.ecdh) {
    crypto_ecdh_deinit(pasn.ecdh);
    pasn.ecdh = NULL;
  }

  eloop_destroy();
  os_program_deinit();

  return 0;
}
