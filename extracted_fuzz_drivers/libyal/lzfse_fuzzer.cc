/*
 * OSS-Fuzz target for libfmos LZFSE decompress function
 *
 * Copyright (C) 2019-2024, Joachim Metz <joachim.metz@gmail.com>
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

#include "ossfuzz_libfmos.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t uncompressed_data[64 * 1024];

  size_t uncompressed_data_size = 64 * 1024;

  libfmos_lzfse_decompress(data, size, uncompressed_data, &uncompressed_data_size, NULL);

  return (0);
}

} /* extern "C" */
