/*
 * OSS-Fuzz target for libvsmbr partition type
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

#include "ossfuzz_libbfio.h"
#include "ossfuzz_libvsmbr.h"

#if !defined(LIBVSMBR_HAVE_BFIO)

/* Opens a volume using a Basic File IO (bfio) handle
 * Returns 1 if successful or -1 on error
 */
LIBVSMBR_EXTERN
int libvsmbr_volume_open_file_io_handle(libvsmbr_volume_t *volume, libbfio_handle_t *file_io_handle, int access_flags, libvsmbr_error_t **error);

#endif /* !defined( LIBVSMBR_HAVE_BFIO ) */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  libbfio_handle_t *file_io_handle = NULL;
  libvsmbr_partition_t *partition = NULL;
  libvsmbr_volume_t *volume = NULL;
  int number_of_partitions = 0;

  if (libbfio_memory_range_initialize(&file_io_handle, NULL) != 1) {
    return (0);
  }
  if (libbfio_memory_range_set(file_io_handle, (uint8_t *)data, size, NULL) != 1) {
    goto on_error_libbfio;
  }
  if (libvsmbr_volume_initialize(&volume, NULL) != 1) {
    goto on_error_libbfio;
  }
  if (libvsmbr_volume_open_file_io_handle(volume, file_io_handle, LIBVSMBR_OPEN_READ, NULL) != 1) {
    goto on_error_libvsmbr_volume;
  }
  if (libvsmbr_volume_get_number_of_partitions(volume, &number_of_partitions, NULL) != 1) {
    goto on_error_libvsmbr_volume;
  }
  if (number_of_partitions > 0) {
    if (libvsmbr_volume_get_partition_by_index(volume, 0, &partition, NULL) == 1) {
      libvsmbr_partition_free(&partition, NULL);
    }
  }
  libvsmbr_volume_close(volume, NULL);

on_error_libvsmbr_volume:
  libvsmbr_volume_free(&volume, NULL);

on_error_libbfio:
  libbfio_handle_free(&file_io_handle, NULL);

  return (0);
}

} /* extern "C" */
