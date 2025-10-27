/*
 * OSS-Fuzz target for libwrc stream type
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

#include "ossfuzz_libbfio.h"
#include "ossfuzz_libwrc.h"

#if !defined(LIBWRC_HAVE_BFIO)

/* Opens a stream using a Basic File IO (bfio) handle
 * Returns 1 if successful or -1 on error
 */
LIBWRC_EXTERN
int libwrc_stream_open_file_io_handle(libwrc_stream_t *stream, libbfio_handle_t *file_io_handle, int access_flags, libwrc_error_t **error);

#endif /* !defined( LIBWRC_HAVE_BFIO ) */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  libbfio_handle_t *file_io_handle = NULL;
  libwrc_stream_t *stream = NULL;

  if (libbfio_memory_range_initialize(&file_io_handle, NULL) != 1) {
    return (0);
  }
  if (libbfio_memory_range_set(file_io_handle, (uint8_t *)data, size, NULL) != 1) {
    goto on_error_libbfio;
  }
  if (libwrc_stream_initialize(&stream, NULL) != 1) {
    goto on_error_libbfio;
  }
  if (libwrc_stream_open_file_io_handle(stream, file_io_handle, LIBWRC_OPEN_READ, NULL) != 1) {
    goto on_error_libwrc;
  }
  libwrc_stream_close(stream, NULL);

on_error_libwrc:
  libwrc_stream_free(&stream, NULL);

on_error_libbfio:
  libbfio_handle_free(&file_io_handle, NULL);

  return (0);
}

} /* extern "C" */
