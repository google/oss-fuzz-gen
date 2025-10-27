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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *ulabel, *alabel;
  char *out;

  if (size > 1024)
    return 0;

  ulabel = (char *)malloc(size + 1);
  assert(ulabel != NULL);

  /* 0 terminate */
  memcpy(ulabel, data, size);
  ulabel[size] = 0;

  if (size == 0) {
    /*** test NULL input/output combinations ***/

    if (idn2_register_ul(NULL, NULL, &out, 0) == IDN2_OK)
      idn2_free(out);
    idn2_register_ul(ulabel, NULL, NULL, 0);
  }

  if (idn2_register_ul(ulabel, NULL, &out, 0) == IDN2_OK)
    idn2_free(out);

  free(ulabel);

  alabel = (char *)malloc(size + 4 + 1);
  assert(alabel != NULL);

  /* 0 terminate */
  memcpy(alabel, "xn--", 4);
  memcpy(alabel + 4, data, size);
  alabel[size] = 0;

  if (idn2_register_ul(NULL, alabel, &out, 0) == IDN2_OK)
    idn2_free(out);

  /*** test NULL input/output combinations ***/
  if (size == 0)
    idn2_register_ul(NULL, alabel, NULL, 0);

  free(alabel);

  return 0;
}
