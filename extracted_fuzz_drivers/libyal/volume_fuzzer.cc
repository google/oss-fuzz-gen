/*
 * OSS-Fuzz target for libbde volume type
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

#include "ossfuzz_libbde.h"
#include "ossfuzz_libbfio.h"

#if !defined(LIBBDE_HAVE_BFIO)

/* Opens a volume using a Basic File IO (bfio) handle
 * Returns 1 if successful or -1 on error
 */
LIBBDE_EXTERN
int libbde_volume_open_file_io_handle(libbde_volume_t *volume, libbfio_handle_t *file_io_handle, int access_flags, libbde_error_t **error);

#endif /* !defined( LIBBDE_HAVE_BFIO ) */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  libbfio_handle_t *file_io_handle = NULL;
  libbde_volume_t *volume = NULL;

  if (libbfio_memory_range_initialize(&file_io_handle, NULL) != 1) {
    return (0);
  }
  if (libbfio_memory_range_set(file_io_handle, (uint8_t *)data, size, NULL) != 1) {
    goto on_error_libbfio;
  }
  if (libbde_volume_initialize(&volume, NULL) != 1) {
    goto on_error_libbfio;
  }
  if (libbde_volume_open_file_io_handle(volume, file_io_handle, LIBBDE_OPEN_READ, NULL) != 1) {
    goto on_error_libbde;
  }
  libbde_volume_close(volume, NULL);

on_error_libbde:
  libbde_volume_free(&volume, NULL);

on_error_libbfio:
  libbfio_handle_free(&file_io_handle, NULL);

  return (0);
}

} /* extern "C" */
