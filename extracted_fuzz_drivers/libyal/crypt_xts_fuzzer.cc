/*
 * OSS-Fuzz target for libcaes AES-ECB crypt function
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
  uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
  uint8_t tweak_key[16] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f};
  uint8_t tweak_value[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

  libcaes_tweaked_context_t *tweaked_context = NULL;

  if (libcaes_tweaked_context_initialize(&tweaked_context, NULL) != 1) {
    return (0);
  }
  if (libcaes_tweaked_context_set_keys(tweaked_context, LIBCAES_CRYPT_MODE_ENCRYPT, key, 128, tweak_key, 128, NULL) != 1) {
    goto on_error_libcaes;
  }
  libcaes_crypt_xts(tweaked_context, LIBCAES_CRYPT_MODE_ENCRYPT, tweak_value, 16, data, size, encrypted_data, 64, NULL);

on_error_libcaes:
  libcaes_tweaked_context_free(&tweaked_context, NULL);

  return (0);
}

} /* extern "C" */
