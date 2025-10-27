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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <assert.h> /* assert */
#include <stdlib.h> /* malloc, free */
#include <string.h> /* memcpy */

#include "fuzzer.h"
#include "idn2.h"

static int flags[] = {0, IDN2_NFC_INPUT, IDN2_TRANSITIONAL, IDN2_NONTRANSITIONAL, IDN2_TRANSITIONAL | IDN2_USE_STD3_ASCII_RULES, IDN2_NONTRANSITIONAL | IDN2_USE_STD3_ASCII_RULES};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *domain;
  char *out;

  if (size > 1024)
    return 0;

  domain = (char *)malloc(size + 1);
  assert(domain != NULL);

  /* 0 terminate */
  memcpy(domain, data, size);
  domain[size] = 0;

  if (size == 0) {
    /*** test NULL input/output combinations ***/

    if (idn2_to_ascii_8z(NULL, &out, 0) == IDN2_OK)
      idn2_free(out);
    idn2_to_ascii_8z(NULL, NULL, 0);
    idn2_to_ascii_8z(domain, NULL, 0);

    if (idn2_to_ascii_lz(NULL, &out, 0) == IDN2_OK)
      idn2_free(out);
    idn2_to_ascii_lz(NULL, NULL, 0);
    idn2_to_ascii_lz(domain, NULL, 0);

    {
      uint32_t in32[1] = {0};
      char out8[1];
      idn2_to_ascii_4i(NULL, 0, out8, 0);
      idn2_to_ascii_4i(NULL, 0, NULL, 0);
      idn2_to_ascii_4i(in32, 0, NULL, 0);
    }

    {
      uint32_t in32[1] = {0};
      if (idn2_to_ascii_4i2(NULL, 0, &out, 0) == IDN2_OK)
        idn2_free(out);
      idn2_to_ascii_4i2(NULL, 0, NULL, 0);
      idn2_to_ascii_4i2(in32, 0, NULL, 0);

      if (idn2_to_ascii_4z(NULL, &out, 0) == IDN2_OK)
        idn2_free(out);
      idn2_to_ascii_4z(NULL, NULL, 0);
      idn2_to_ascii_4z(in32, NULL, 0);
    }
  }

  for (unsigned it = 0; it < sizeof(flags) / sizeof(flags[0]); it++) {
    if (idn2_to_ascii_8z(domain, &out, flags[it]) == IDN2_OK)
      idn2_free(out);
    if (idn2_to_ascii_lz(domain, &out, flags[it]) == IDN2_OK)
      idn2_free(out);
  }

  if ((size & 3) == 0) {
    uint32_t *u32 = (uint32_t *)malloc(size + 4);
    char *out2 = (char *)malloc(64);

    assert(u32 != NULL);
    assert(out2 != NULL);

    idn2_to_ascii_4i((uint32_t *)data, size / 4, out2, 0);

    for (unsigned it = 0; it < sizeof(flags) / sizeof(flags[0]); it++)
      if (idn2_to_ascii_4i2((uint32_t *)data, size / 4, &out, flags[it]) == IDN2_OK)
        idn2_free(out);

    memcpy(u32, data, size);
    u32[size / 4] = 0;

    for (unsigned it = 0; it < sizeof(flags) / sizeof(flags[0]); it++)
      if (idn2_to_ascii_4z(u32, &out, flags[it]) == IDN2_OK)
        idn2_free(out);

    free(out2);
    free(u32);
  }

  free(domain);
  return 0;
}
