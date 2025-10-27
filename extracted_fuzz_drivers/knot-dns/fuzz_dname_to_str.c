/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "libknot/dname.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Skip invalid dnames.
  if (knot_dname_wire_check(data, data + size, NULL) <= 0) {
    return 0;
  }

  // Transform the input.
  knot_dname_txt_storage_t txt;
  (void)knot_dname_to_str(txt, (const knot_dname_t *)data, sizeof(txt));

  return 0;
}
