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
#include "idna.h"

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

  if ((size & 3) == 0) {
    uint32_t *u32 = (uint32_t *)malloc(size);
    size_t u32len;

    assert(u32 != NULL);

    u32len = size / 4;
    idna_to_unicode_44i((uint32_t *)data, size / 4, u32, &u32len, 0);
    u32len = size / 4;
    idna_to_unicode_44i((uint32_t *)data, size / 4, u32, &u32len, IDNA_ALLOW_UNASSIGNED | IDNA_USE_STD3_ASCII_RULES);

    free(u32);

    uint32_t *data0 = (uint32_t *)malloc(size + 4), *out0;
    assert(data0 != NULL);
    memcpy(data0, data, size);
    data0[size / 4] = 0;

    if (idna_to_unicode_4z4z(data0, &out0, 0) == IDNA_SUCCESS)
      idn_free(out0);
    if (idna_to_unicode_4z4z(data0, &out0, IDNA_ALLOW_UNASSIGNED | IDNA_USE_STD3_ASCII_RULES) == IDNA_SUCCESS)
      idn_free(out0);

    free(data0);

    if (idna_to_unicode_8z4z(domain, &out0, 0) == IDNA_SUCCESS)
      idn_free(out0);
    if (idna_to_unicode_8z4z(domain, &out0, IDNA_ALLOW_UNASSIGNED | IDNA_USE_STD3_ASCII_RULES) == IDNA_SUCCESS)
      idn_free(out0);
  }

  if (idna_to_unicode_8z8z(domain, &out, 0) == IDNA_SUCCESS)
    idn_free(out);
  if (idna_to_unicode_8z8z(domain, &out, IDNA_ALLOW_UNASSIGNED | IDNA_USE_STD3_ASCII_RULES) == IDNA_SUCCESS)
    idn_free(out);
  if (idna_to_unicode_8zlz(domain, &out, 0) == IDNA_SUCCESS)
    idn_free(out);
  if (idna_to_unicode_8zlz(domain, &out, IDNA_ALLOW_UNASSIGNED | IDNA_USE_STD3_ASCII_RULES) == IDNA_SUCCESS)
    idn_free(out);
  if (idna_to_unicode_lzlz(domain, &out, 0) == IDNA_SUCCESS)
    idn_free(out);
  if (idna_to_unicode_lzlz(domain, &out, IDNA_ALLOW_UNASSIGNED | IDNA_USE_STD3_ASCII_RULES) == IDNA_SUCCESS)
    idn_free(out);

  free(domain);

  return 0;
}
