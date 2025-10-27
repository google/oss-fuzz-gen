/*
 * OSS-Fuzz target for libfsapfs container type
 *
 * Copyright (C) 2018-2024, Joachim Metz <joachim.metz@gmail.com>
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
#include "ossfuzz_libfsapfs.h"

#if !defined(LIBFSAPFS_HAVE_BFIO)

/* Opens a container using a Basic File IO (bfio) handle
 * Returns 1 if successful or -1 on error
 */
LIBFSAPFS_EXTERN
int libfsapfs_container_open_file_io_handle(libfsapfs_container_t *container, libbfio_handle_t *file_io_handle, int access_flags, libfsapfs_error_t **error);

#endif /* !defined( LIBFSAPFS_HAVE_BFIO ) */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  libbfio_handle_t *file_io_handle = NULL;
  libfsapfs_container_t *container = NULL;

  if (libbfio_memory_range_initialize(&file_io_handle, NULL) != 1) {
    return (0);
  }
  if (libbfio_memory_range_set(file_io_handle, (uint8_t *)data, size, NULL) != 1) {
    goto on_error_libbfio;
  }
  if (libfsapfs_container_initialize(&container, NULL) != 1) {
    goto on_error_libbfio;
  }
  if (libfsapfs_container_open_file_io_handle(container, file_io_handle, LIBFSAPFS_OPEN_READ, NULL) != 1) {
    goto on_error_libfsapfs;
  }
  libfsapfs_container_close(container, NULL);

on_error_libfsapfs:
  libfsapfs_container_free(&container, NULL);

on_error_libbfio:
  libbfio_handle_free(&file_io_handle, NULL);

  return (0);
}

} /* extern "C" */
