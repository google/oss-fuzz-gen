/*
 * OSS-Fuzz target for libcreg value type
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

#include "ossfuzz_libbfio.h"
#include "ossfuzz_libcreg.h"

#if !defined(LIBCREG_HAVE_BFIO)

/* Opens a file using a Basic File IO (bfio) handle
 * Returns 1 if successful or -1 on error
 */
LIBCREG_EXTERN
int libcreg_file_open_file_io_handle(libcreg_file_t *file, libbfio_handle_t *file_io_handle, int access_flags, libcreg_error_t **error);

#endif /* !defined( LIBCREG_HAVE_BFIO ) */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  libbfio_handle_t *file_io_handle = NULL;
  libcreg_file_t *file = NULL;
  libcreg_key_t *root_key = NULL;
  libcreg_key_t *sub_key = NULL;
  libcreg_value_t *value = NULL;
  uint32_t value_type = 0;
  int number_of_sub_keys = 0;
  int number_of_values = 0;

  if (libbfio_memory_range_initialize(&file_io_handle, NULL) != 1) {
    return (0);
  }
  if (libbfio_memory_range_set(file_io_handle, (uint8_t *)data, size, NULL) != 1) {
    goto on_error_libbfio;
  }
  if (libcreg_file_initialize(&file, NULL) != 1) {
    goto on_error_libbfio;
  }
  if (libcreg_file_open_file_io_handle(file, file_io_handle, LIBCREG_OPEN_READ, NULL) != 1) {
    goto on_error_libcreg_file;
  }
  if (libcreg_file_get_root_key(file, &root_key, NULL) == 1) {
    if (libcreg_key_get_number_of_sub_keys(root_key, &number_of_sub_keys, NULL) != 1) {
      goto on_error_libcreg_root_key;
    }
    if (number_of_sub_keys > 0) {
      if (libcreg_key_get_sub_key_by_index(root_key, 0, &sub_key, NULL) != 1) {
        goto on_error_libcreg_root_key;
      }
      if (libcreg_key_get_number_of_values(sub_key, &number_of_values, NULL) != 1) {
        goto on_error_libcreg_sub_key;
      }
      if (number_of_sub_keys > 0) {
        if (libcreg_key_get_value_by_index(root_key, 0, &value, NULL) != 1) {
          goto on_error_libcreg_sub_key;
        }
        libcreg_value_get_value_type(value, &value_type, NULL);

        libcreg_value_free(&value, NULL);
      }
    on_error_libcreg_sub_key:
      libcreg_key_free(&sub_key, NULL);
    }
  on_error_libcreg_root_key:
    libcreg_key_free(&root_key, NULL);
  }
  libcreg_file_close(file, NULL);

on_error_libcreg_file:
  libcreg_file_free(&file, NULL);

on_error_libbfio:
  libbfio_handle_free(&file_io_handle, NULL);

  return (0);
}

} /* extern "C" */
