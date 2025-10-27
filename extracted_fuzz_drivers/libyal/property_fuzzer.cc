/*
 * OSS-Fuzz target for libfplist property type
 *
 * Copyright (C) 2016-2024, Joachim Metz <joachim.metz@gmail.com>
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

#include "ossfuzz_libfplist.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  libfplist_property_t *root_property = NULL;
  libfplist_property_list_t *property_list = NULL;
  int value_type = 0;

  if (libfplist_property_list_initialize(&property_list, NULL) != 1) {
    return (0);
  }
  if (libfplist_property_list_copy_from_byte_stream(property_list, data, size, NULL) != 1) {
    goto on_error_libfplist_property_list;
  }
  if (libfplist_property_list_get_root_property(property_list, &root_property, NULL) == 1) {
    libfplist_property_get_value_type(root_property, &value_type, NULL);

    libfplist_property_free(&root_property, NULL);
  }
on_error_libfplist_property_list:
  libfplist_property_list_free(&property_list, NULL);

  return (0);
}

} /* extern "C" */
