/*
 * OSS-Fuzz target for libfwps set type
 *
 * Copyright (C) 2013-2024, Joachim Metz <joachim.metz@gmail.com>
 *
 * Refer to AUTHORS for acknowledgements.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stddef.h>
#include <stdint.h>

/* Note that some of the OSS-Fuzz engines use C++
 */
extern "C" {

#include "ossfuzz_libfwps.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  libfwps_set_t *set = NULL;

  if (libfwps_set_initialize(&set, NULL) != 1) {
    return (0);
  }
  libfwps_set_copy_from_byte_stream(set, data, size, LIBFWPS_CODEPAGE_WINDOWS_1252, NULL);

  libfwps_set_free(&set, NULL);

  return (0);
}

} /* extern "C" */
