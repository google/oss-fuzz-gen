/*
    RawSpeed - RAW file decoder.

    Copyright (C) 2023 Roman Lebedev

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

#include "decompressors/LJpegDecompressor.h"
#include "MemorySanitizer.h"
#include "adt/Casts.h"
#include "adt/Point.h"
#include "codes/PrefixCodeDecoder.h"
#include "codes/PrefixCodeDecoder/Common.h"
#include "common/RawImage.h"
#include "common/RawspeedException.h"
#include "fuzz/Common.h"
#include "io/Buffer.h"
#include "io/ByteStream.h"
#include "io/Endianness.h"
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  assert(Data);

  try {
    const rawspeed::Buffer b(Data, rawspeed::implicit_cast<rawspeed::Buffer::size_type>(Size));
    const rawspeed::DataBuffer db(b, rawspeed::Endianness::little);
    rawspeed::ByteStream bs(db);

    rawspeed::RawImage mRaw(CreateRawImage(bs));

    const int N_COMP = bs.getI32();
    const int frame_w = bs.getI32();
    const int frame_h = bs.getI32();
    const rawspeed::LJpegDecompressor::Frame frame{N_COMP, rawspeed::iPoint2D(frame_w, frame_h)};

    const unsigned num_recips = bs.getU32();

    const unsigned num_unique_hts = bs.getU32();
    std::vector<rawspeed::PrefixCodeDecoder<>> uniqueHts;
    std::generate_n(std::back_inserter(uniqueHts), num_unique_hts, [&bs]() { return createPrefixCodeDecoder<rawspeed::PrefixCodeDecoder<>>(bs); });

    std::vector<const rawspeed::PrefixCodeDecoder<> *> hts;
    std::generate_n(std::back_inserter(hts), num_recips, [&bs, &uniqueHts]() {
      if (unsigned uniq_ht_idx = bs.getU32(); uniq_ht_idx < uniqueHts.size())
        return &uniqueHts[uniq_ht_idx];
      ThrowRSE("Unknown unique huffman table");
    });

    (void)bs.check(num_recips, sizeof(uint16_t));
    std::vector<uint16_t> initPred;
    initPred.reserve(num_recips);
    std::generate_n(std::back_inserter(initPred), num_recips, [&bs]() { return bs.get<uint16_t>(); });

    std::vector<rawspeed::LJpegDecompressor::PerComponentRecipe> rec;
    rec.reserve(num_recips);
    std::generate_n(std::back_inserter(rec), num_recips, [&rec, hts, initPred]() -> rawspeed::LJpegDecompressor::PerComponentRecipe {
      const auto i = rawspeed::implicit_cast<int>(rec.size());
      return {*hts[i], initPred[i]};
    });

    rawspeed::LJpegDecompressor d(mRaw, rawspeed::iRectangle2D(mRaw->dim.x, mRaw->dim.y), frame, rec, bs.getSubStream(/*offset=*/0));
    mRaw->createData();
    d.decode();

    rawspeed::MSan::CheckMemIsInitialized(mRaw->getByteDataAsUncroppedArray2DRef());
  } catch (const rawspeed::RawspeedException &) { // NOLINT(bugprone-empty-catch)
    // Exceptions are good, crashes are bad.
  }

  return 0;
}
