/*
 * OSS-Fuzz target for libvslvm handle type
 *
 * Copyright (C) 2014-2024, Joachim Metz <joachim.metz@gmail.com>
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
#include "ossfuzz_libvslvm.h"

#if !defined(LIBVSLVM_HAVE_BFIO)

/* Opens a handle using a Basic File IO (bfio) handle
 * Returns 1 if successful or -1 on error
 */
LIBVSLVM_EXTERN
int libvslvm_handle_open_file_io_handle(libvslvm_handle_t *handle, libbfio_handle_t *file_io_handle, int access_flags, libvslvm_error_t **error);

/* Opens the physical volume files
 * This function assumes the physical volume files are in same order as defined by the metadata
 * Returns 1 if successful or -1 on error
 */
LIBVSLVM_EXTERN
int libvslvm_handle_open_physical_volume_files_file_io_pool(libvslvm_handle_t *handle, libbfio_pool_t *file_io_pool, libvslvm_error_t **error);

#endif /* !defined( LIBVSLVM_HAVE_BFIO ) */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  libbfio_handle_t *file_io_handle = NULL;
  libbfio_pool_t *file_io_pool = NULL;
  libvslvm_handle_t *handle = NULL;
  libvslvm_logical_volume_t *logical_volume = NULL;
  libvslvm_volume_group_t *volume_group = NULL;
  int entry_index = 0;
  int number_of_logical_volumes = 0;

  if (libbfio_memory_range_initialize(&file_io_handle, NULL) != 1) {
    return (0);
  }
  if (libbfio_memory_range_set(file_io_handle, (uint8_t *)data, size, NULL) != 1) {
    goto on_error_libbfio;
  }
  if (libbfio_pool_initialize(&file_io_pool, 0, 0, NULL) != 1) {
    goto on_error_libbfio;
  }
  if (libvslvm_handle_initialize(&handle, NULL) != 1) {
    goto on_error_libbfio;
  }
  if (libvslvm_handle_open_file_io_handle(handle, file_io_handle, LIBVSLVM_OPEN_READ, NULL) != 1) {
    goto on_error_libvslvm_handle;
  }
  if (libbfio_pool_append_handle(file_io_pool, &entry_index, file_io_handle, LIBBFIO_OPEN_READ, NULL) != 1) {
    goto on_error_libvslvm_handle;
  }
  /* The file IO pool takes over management of the file IO handle
   */
  file_io_handle = NULL;

  if (libvslvm_handle_open_physical_volume_files_file_io_pool(handle, file_io_pool, NULL) != 1) {
    goto on_error_libvslvm_handle;
  }
  if (libvslvm_handle_get_volume_group(handle, &volume_group, NULL) == 1) {
    if (libvslvm_volume_group_get_number_of_logical_volumes(volume_group, &number_of_logical_volumes, NULL) != 1) {
      goto on_error_libvslvm_volume_group;
    }
    if (number_of_logical_volumes > 0) {
      if (libvslvm_volume_group_get_logical_volume(volume_group, 0, &logical_volume, NULL) == 1) {
        libvslvm_logical_volume_free(&logical_volume, NULL);
      }
    }
  on_error_libvslvm_volume_group:
    libvslvm_volume_group_free(&volume_group, NULL);
  }
  libvslvm_handle_close(handle, NULL);

on_error_libvslvm_handle:
  libvslvm_handle_free(&handle, NULL);

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
