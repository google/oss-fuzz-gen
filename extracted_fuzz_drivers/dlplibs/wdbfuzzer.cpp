/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* libwps
 * Version: MPL 2.0 / LGPLv2.1+
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Major Contributor(s):
 * Copyright (C) 2017 David Tardon (dtardon@redhat.com)
 *
 * For minor contributions see the git repository.
 *
 * Alternatively, the contents of this file may be used under the terms
 * of the GNU Lesser General Public License Version 2.1 or later
 * (LGPLv2.1+), in which case the provisions of the LGPLv2.1+ are
 * applicable instead of those above.
 */

#include <cstdint>
#include <cstdlib>

#include <librevenge-generators/RVNGDummySpreadsheetGenerator.h>

#include <librevenge-stream/librevenge-stream.h>

#include <libwps/libwps.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  librevenge::RVNGStringStream input(data, size);
  librevenge::RVNGDummySpreadsheetGenerator generator;
  libwps::WPSDocument::parse(&input, &generator);
  return 0;
}

/* vim:set shiftwidth=4 softtabstop=4 noexpandtab: */
