/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* librevenge
 * Version: MPL 2.0 / LGPLv2.1+
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Alternatively, the contents of this file may be used under the terms
 * of the GNU Lesser General Public License Version 2.1 or later
 * (LGPLv2.1+), in which case the provisions of the LGPLv2.1+ are
 * applicable instead of those above.
 */

#include <cstdint>
#include <cstdlib>

#include <librevenge-stream/librevenge-stream.h>

#include "commonfuzzer.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  librevenge::RVNGStringStream input(data, size);
  fuzz::testStructuredStream(input);
  return 0;
}

/* vim:set shiftwidth=2 softtabstop=2 expandtab: */
