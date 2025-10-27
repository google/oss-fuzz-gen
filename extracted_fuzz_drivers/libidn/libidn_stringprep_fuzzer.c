/*
 * Copyright(c) 2017 Tim Ruehsen
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <assert.h> /* assert */
#include <stdint.h> /* uint8_t, uint32_t */
#include <stdlib.h> /* malloc, free */
#include <string.h> /* memcpy */

#include "fuzzer.h"
#include "idn-free.h"
#include "pr29.h"
#include "stringprep.h"
#include "tld.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *wdata;
  char *label;
  char *utf8_seq;
  char *out;
  uint32_t cp;
  size_t errpos;

  if (size > 2048)
    return 0;

  wdata = (char *)malloc(size + 1);
  label = (char *)malloc(size + 1);
  utf8_seq = (char *)malloc(6);
  assert(wdata != NULL);
  assert(label != NULL);
  assert(utf8_seq != NULL);

  /* 0 terminate */
  memcpy(label, data, size);
  label[size] = 0;

  stringprep_check_version(label);

  if (stringprep_profile(label, &out, "Nodeprep", (Stringprep_profile_flags)0) == STRINGPREP_OK)
    idn_free(out);

  pr29_8z(label); /* internally calls stringprep_utf8_to_ucs4() */

#ifdef WITH_TLD
  if (tld_get_z(label, &out) == TLD_SUCCESS) /* internally calls tld_get_4() */
    idn_free(out);
  const Tld_table *tld = tld_default_table("fr", NULL);
  tld_check_8z(label, &errpos, NULL);
  tld_check_lz(label, &errpos, NULL);
#endif

  out = stringprep_utf8_nfkc_normalize((char *)data, size);
  idn_free(out);

  cp = stringprep_utf8_to_unichar(label);
  stringprep_unichar_to_utf8(cp, utf8_seq);

  memcpy(wdata, data, size);
  wdata[size] = 0;
  stringprep(wdata, size, (Stringprep_profile_flags)0, stringprep_nameprep);
  memcpy(wdata, data, size);
  wdata[size] = 0;
  stringprep(wdata, size, STRINGPREP_NO_UNASSIGNED, stringprep_nameprep);

  if ((size & 3) == 0) {
    uint32_t *u32 = (uint32_t *)malloc(size + 4);

    assert(u32 != NULL);

    memcpy(u32, data, size);
    u32[size / 4] = 0;
    stringprep_4zi(u32, size / 4, (Stringprep_profile_flags)0, stringprep_xmpp_nodeprep);

    memcpy(u32, data, size);
    u32[size / 4] = 0;
#ifdef WITH_TLD
    if (tld_get_4z(u32, &out) == TLD_SUCCESS) /* internally calls tld_get_4() */
      idn_free(out);

    tld_check_4tz(u32, &errpos, tld);
    tld_check_4z(u32, &errpos, NULL);
#endif

    free(u32);
  }

  free(utf8_seq);
  free(label);
  free(wdata);

  return 0;
}
