/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This file is part of the libmspub project.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <cstdint>
#include <cstdlib>

#include <librevenge-generators/RVNGDummyTextGenerator.h>

#include <librevenge-stream/librevenge-stream.h>

#include <libwpd/libwpd.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  librevenge::RVNGStringStream input(data, size);
  librevenge::RVNGDummyTextGenerator generator;
  libwpd::WPDocument::parse(&input, &generator, "");
  return 0;
}

/* vim:set shiftwidth=4 softtabstop=4 noexpandtab: */
