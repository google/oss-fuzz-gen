/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdint.h>

#include "libzscanner/scanner.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  zs_scanner_t s;
  if (zs_init(&s, ".", 1, 0) == 0 && zs_set_input_string(&s, (const char *)data, size) == 0) {
    zs_parse_all(&s);
  }
  zs_deinit(&s);

  return 0;
}
