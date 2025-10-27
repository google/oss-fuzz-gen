/*
 * OSS-Fuzz target for libfmapi one_off_entry_identifier type
 *
 * Copyright (C) 2011-2024, Joachim Metz <joachim.metz@gmail.com>
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

#include "ossfuzz_libfmapi.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  libfmapi_one_off_entry_identifier_t *one_off_entry_identifier = NULL;

  if (libfmapi_one_off_entry_identifier_initialize(&one_off_entry_identifier, NULL) != 1) {
    return (0);
  }
  /* TODO replace 1252 by codepage definition */
  libfmapi_one_off_entry_identifier_copy_from_byte_stream(one_off_entry_identifier, data, size, 1252, NULL);

  libfmapi_one_off_entry_identifier_free(&one_off_entry_identifier, NULL);

  return (0);
}

} /* extern "C" */
