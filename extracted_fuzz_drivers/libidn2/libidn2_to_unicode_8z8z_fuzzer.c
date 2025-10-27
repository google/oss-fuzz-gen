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
#include <stdint.h> /* uint8_t, uint32_t */
#include <stdlib.h> /* malloc, free */
#include <string.h> /* memcpy */

#include "fuzzer.h"
#include "idn2.h"

#pragma GCC optimize("O0")

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *domain;
  char *out;
  const char *x = "";

  if (size > 1024)
    return 0;

  domain = (char *)malloc(size + 1);
  assert(domain != NULL);

  // 0 terminate
  memcpy(domain, data, size);
  domain[size] = 0;

  if (size == 0) {
    x = idn2_check_version(NULL);

    for (int err = -500; err <= 0; err++) {
      if (idn2_strerror_name(err))
        x = NULL;
      if (idn2_strerror(err))
        x = NULL;
    }

    /*** test NULL input/output combinations ***/

    if (idn2_to_unicode_lzlz(NULL, &out, 0) == IDN2_OK)
      idn2_free(out);
    idn2_to_unicode_lzlz(NULL, NULL, 0);
    idn2_to_unicode_lzlz(domain, NULL, 0);

    {
      uint32_t *in32 = (uint32_t *)malloc(4);
      uint32_t *out32;
      in32[0] = 0;
      if (idn2_to_unicode_4z4z(NULL, &out32, 0) == IDN2_OK)
        idn2_free(out32);
      idn2_to_unicode_4z4z(NULL, NULL, 0);
      idn2_to_unicode_4z4z(in32, NULL, 0);
      free(in32);
    }

    {
      uint32_t *out32;
      if (idn2_to_unicode_8z4z(NULL, &out32, 0) == IDN2_OK)
        idn2_free(out32);
      idn2_to_unicode_8z4z(NULL, NULL, 0);
      idn2_to_unicode_8z4z(domain, NULL, 0);
    }

    {
      uint32_t *u32 = (uint32_t *)malloc(0);
      size_t u32len = 0;
      idn2_to_unicode_44i(NULL, 1, u32, &u32len, 0);
      u32len = 0;
      idn2_to_unicode_44i(NULL, 0, NULL, &u32len, 0);
      free(u32);
    }
  }

  // let's fuzz gnulib's strverscmp()
  if (idn2_check_version(domain))
    x = NULL;

  if (x)
    free(malloc(1)); // prevent compiler from optimizing out idn2_check_version()

  // internally calls idn2_to_unicode_8zlz(), idn2_to_unicode_8z8z(), idn2_to_unicode_8z4z()
  if (idn2_to_unicode_lzlz(domain, &out, 0) == IDN2_OK)
    idn2_free(out);

  if ((size & 3) == 0) {
    uint32_t *u32 = (uint32_t *)malloc(size);
    size_t u32len;

    assert(u32 != NULL);

    // internally calls idn2_to_unicode_4z4z(), idn2_to_unicode_8z4z()
    u32len = size / 4;
    idn2_to_unicode_44i((uint32_t *)data, size / 4, u32, &u32len, 0);

    free(u32);
  }

  free(domain);
  return 0;
}
