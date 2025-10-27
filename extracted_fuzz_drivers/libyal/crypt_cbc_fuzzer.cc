/*
 * OSS-Fuzz target for libcaes AES-CBC crypt function
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

#include "ossfuzz_libcaes.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t encrypted_data[64];
  uint8_t initialization_vector[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
  uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

  libcaes_context_t *context = NULL;

  if (libcaes_context_initialize(&context, NULL) != 1) {
    return (0);
  }
  if (libcaes_context_set_key(context, LIBCAES_CRYPT_MODE_ENCRYPT, key, 128, NULL) != 1) {
    goto on_error_libcaes;
  }
  libcaes_crypt_cbc(context, LIBCAES_CRYPT_MODE_ENCRYPT, initialization_vector, 16, data, size, encrypted_data, 64, NULL);

on_error_libcaes:
  libcaes_context_free(&context, NULL);

  return (0);
}

} /* extern "C" */
