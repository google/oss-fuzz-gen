/*
 * OSS-Fuzz target for libewf file type
 *
 * Copyright (C) 2006-2024, Joachim Metz <joachim.metz@gmail.com>
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
#include "ossfuzz_libewf.h"

#if !defined(LIBEWF_HAVE_BFIO)

/* Opens a set of EWF file(s) using a Basic File IO (bfio) pool
 * Returns 1 if successful or -1 on error
 */
LIBEWF_EXTERN
int libewf_handle_open_file_io_pool(libewf_handle_t *handle, libbfio_pool_t *file_io_pool, int access_flags, libewf_error_t **error);

#endif /* !defined( LIBEWF_HAVE_BFIO ) */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  libbfio_handle_t *file_io_handle = NULL;
  libbfio_pool_t *file_io_pool = NULL;
  libewf_handle_t *handle = NULL;
  int entry_index = 0;

  if (libbfio_memory_range_initialize(&file_io_handle, NULL) != 1) {
    return (0);
  }
  if (libbfio_memory_range_set(file_io_handle, (uint8_t *)data, size, NULL) != 1) {
    goto on_error_libbfio;
  }
  if (libbfio_pool_initialize(&file_io_pool, 0, 0, NULL) != 1) {
    goto on_error_libbfio;
  }
  if (libbfio_pool_append_handle(file_io_pool, &entry_index, file_io_handle, LIBBFIO_OPEN_READ, NULL) != 1) {
    goto on_error_libbfio;
  }
  /* The file IO pool takes over management of the file IO handle
   */
  file_io_handle = NULL;

  if (libewf_handle_initialize(&handle, NULL) != 1) {
    goto on_error_libbfio;
  }
  if (libewf_handle_open_file_io_pool(handle, file_io_pool, LIBEWF_OPEN_READ, NULL) != 1) {
    goto on_error_libewf;
  }
  libewf_handle_close(handle, NULL);

on_error_libewf:
  libewf_handle_free(&handle, NULL);

on_error_libbfio:
  /* Note that on error the handle still has a reference to file_io_pool
   * that will be closed. Therefore the file IO pool and handle need to
   * be freed after closing or freeing the handle.
   */
  if (file_io_pool != NULL) {
    libbfio_pool_free(&file_io_pool, NULL);
  }
  if (file_io_handle != NULL) {
    libbfio_handle_free(&file_io_handle, NULL);
  }
  return (0);
}

} /* extern "C" */
