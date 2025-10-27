/*
    RawSpeed - RAW file decoder.

    Copyright (C) 2018 Roman Lebedev

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
*/

#include "decompressors/PhaseOneDecompressor.h"
#include "MemorySanitizer.h"
#include "adt/Casts.h"
#include "common/RawImage.h"
#include "common/RawspeedException.h"
#include "fuzz/Common.h"
#include "io/Buffer.h"
#include "io/ByteStream.h"
#include "io/Endianness.h"
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <iterator>
#include <utility>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  assert(Data);

  try {
    const rawspeed::Buffer b(Data, rawspeed::implicit_cast<rawspeed::Buffer::size_type>(Size));
    const rawspeed::DataBuffer db(b, rawspeed::Endianness::little);
    rawspeed::ByteStream bs(db);

    rawspeed::RawImage mRaw(CreateRawImage(bs));

    const auto numStrips = bs.getU32();
    std::vector<rawspeed::PhaseOneStrip> strips;
    std::generate_n(std::back_inserter(strips), numStrips, [&bs]() -> rawspeed::PhaseOneStrip {
      const int n = bs.getU32();
      const auto stripLen = bs.getU32();
      return {n, bs.getStream(stripLen)};
    });
    assert(strips.size() == numStrips);

    rawspeed::PhaseOneDecompressor f(mRaw, std::move(strips));
    mRaw->createData();
    f.decompress();

    rawspeed::MSan::CheckMemIsInitialized(mRaw->getByteDataAsUncroppedArray2DRef());
  } catch (const rawspeed::RawspeedException &) { // NOLINT(bugprone-empty-catch)
    // Exceptions are good, crashes are bad.
  }

  return 0;
}
