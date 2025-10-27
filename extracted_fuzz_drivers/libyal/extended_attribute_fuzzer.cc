/*
 * OSS-Fuzz target for libfsxfs extended_attribute type
 *
 * Copyright (C) 2020-2024, Joachim Metz <joachim.metz@gmail.com>
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
#include "ossfuzz_libfsxfs.h"

#if !defined(LIBFSXFS_HAVE_BFIO)

/* Opens a volume using a Basic File IO (bfio) handle
 * Returns 1 if successful or -1 on error
 */
LIBFSXFS_EXTERN
int libfsxfs_volume_open_file_io_handle(libfsxfs_volume_t *volume, libbfio_handle_t *file_io_handle, int access_flags, libfsxfs_error_t **error);

#endif /* !defined( LIBFSXFS_HAVE_BFIO ) */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  libbfio_handle_t *file_io_handle = NULL;
  libfsxfs_extended_attribute_t *extended_attribute = NULL;
  libfsxfs_file_entry_t *file_entry = NULL;
  libfsxfs_volume_t *volume = NULL;
  int number_of_extended_attributes = 0;
  int result = 0;

  if (libbfio_memory_range_initialize(&file_io_handle, NULL) != 1) {
    return (0);
  }
  if (libbfio_memory_range_set(file_io_handle, (uint8_t *)data, size, NULL) != 1) {
    goto on_error_libbfio;
  }
  if (libfsxfs_volume_initialize(&volume, NULL) != 1) {
    goto on_error_libbfio;
  }
  if (libfsxfs_volume_open_file_io_handle(volume, file_io_handle, LIBFSXFS_OPEN_READ, NULL) != 1) {
    goto on_error_libfsxfs_volume;
  }
  result = libfsxfs_volume_get_file_entry_by_utf8_path(volume, (uint8_t *)"/a_directory/a_file", 19, &file_entry, NULL);

  if (result == 1) {
    if (libfsxfs_file_entry_get_number_of_extended_attributes(file_entry, &number_of_extended_attributes, NULL) != 1) {
      goto on_error_libfsxfs_file_entry;
    }
    if (number_of_extended_attributes > 0) {
      if (libfsxfs_file_entry_get_extended_attribute_by_index(file_entry, 0, &extended_attribute, NULL) != 1) {
        goto on_error_libfsxfs_file_entry;
      }
      libfsxfs_extended_attribute_free(&extended_attribute, NULL);
    }
  on_error_libfsxfs_file_entry:
    libfsxfs_file_entry_free(&file_entry, NULL);
  }
  libfsxfs_volume_close(volume, NULL);

on_error_libfsxfs_volume:
  libfsxfs_volume_free(&volume, NULL);

on_error_libbfio:
  libbfio_handle_free(&file_io_handle, NULL);

  return (0);
}

} /* extern "C" */
