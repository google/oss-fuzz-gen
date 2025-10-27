/*
 * OSS-Fuzz target for libolecf item type
 *
 * Copyright (C) 2008-2024, Joachim Metz <joachim.metz@gmail.com>
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
#include "ossfuzz_libolecf.h"

#if !defined(LIBOLECF_HAVE_BFIO)

/* Opens a file using a Basic File IO (bfio) handle
 * Returns 1 if successful or -1 on error
 */
LIBOLECF_EXTERN
int libolecf_file_open_file_io_handle(libolecf_file_t *file, libbfio_handle_t *file_io_handle, int access_flags, libolecf_error_t **error);

#endif /* !defined( LIBOLECF_HAVE_BFIO ) */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  libbfio_handle_t *file_io_handle = NULL;
  libolecf_file_t *file = NULL;
  libolecf_item_t *root_item = NULL;
  libolecf_item_t *sub_item = NULL;
  int number_of_sub_items = 0;

  if (libbfio_memory_range_initialize(&file_io_handle, NULL) != 1) {
    return (0);
  }
  if (libbfio_memory_range_set(file_io_handle, (uint8_t *)data, size, NULL) != 1) {
    goto on_error_libbfio;
  }
  if (libolecf_file_initialize(&file, NULL) != 1) {
    goto on_error_libbfio;
  }
  if (libolecf_file_open_file_io_handle(file, file_io_handle, LIBOLECF_OPEN_READ, NULL) != 1) {
    goto on_error_libolecf_file;
  }
  if (libolecf_file_get_root_item(file, &root_item, NULL) == 1) {
    if (libolecf_item_get_number_of_sub_items(root_item, &number_of_sub_items, NULL) != 1) {
      goto on_error_libolecf_root_item;
    }
    if (number_of_sub_items > 0) {
      if (libolecf_item_get_sub_item(root_item, 0, &sub_item, NULL) != 1) {
        goto on_error_libolecf_root_item;
      }
      libolecf_item_free(&sub_item, NULL);
    }
  on_error_libolecf_root_item:
    libolecf_item_free(&root_item, NULL);
  }
  libolecf_file_close(file, NULL);

on_error_libolecf_file:
  libolecf_file_free(&file, NULL);

on_error_libbfio:
  libbfio_handle_free(&file_io_handle, NULL);

  return (0);
}

} /* extern "C" */
