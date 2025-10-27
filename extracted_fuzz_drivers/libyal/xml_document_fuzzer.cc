/*
 * OSS-Fuzz target for libfwevt xml_document type
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

#include "ossfuzz_libfwevt.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  libfwevt_xml_document_t *xml_document = NULL;

  if (libfwevt_xml_document_initialize(&xml_document, NULL) != 1) {
    return (0);
  }
  libfwevt_xml_document_read(xml_document, data, size, 0, 1252, LIBFWEVT_XML_DOCUMENT_READ_FLAG_HAS_DATA_OFFSETS | LIBFWEVT_XML_DOCUMENT_READ_FLAG_HAS_DATA_OFFSETS, NULL);

  libfwevt_xml_document_free(&xml_document, NULL);

  return (0);
}

} /* extern "C" */
