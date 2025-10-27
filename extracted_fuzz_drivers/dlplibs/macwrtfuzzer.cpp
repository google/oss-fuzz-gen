/* -*- Mode: C++; c-default-style: "k&r"; indent-tabs-mode: nil; tab-width: 2; c-basic-offset: 2 -*- */

/* libmwaw
 * Version: MPL 2.0 / LGPLv2+
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 2.0 (the "License"); you may not use this file except in compliance with
 * the License or as specified alternatively below. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * Major Contributor(s):
 * Copyright (C) 2017 David Tardon (dtardon@redhat.com)
 *
 *
 * All Rights Reserved.
 *
 * For minor contributions see the git repository.
 *
 * Alternatively, the contents of this file may be used under the terms of
 * the GNU Lesser General Public License Version 2 or later (the "LGPLv2+"),
 * in which case the provisions of the LGPLv2+ are applicable
 * instead of those above.
 */

#include <cstdint>
#include <cstdlib>

#include <libmwaw/libmwaw.hxx>

#include <librevenge-generators/RVNGDummyTextGenerator.h>

#include <librevenge-stream/librevenge-stream.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  librevenge::RVNGStringStream input(data, size);
  librevenge::RVNGDummyTextGenerator generator;
  MWAWDocument::parse(&input, &generator);
  return 0;
}

// vim: set filetype=cpp tabstop=2 shiftwidth=2 cindent autoindent smartindent noexpandtab:
