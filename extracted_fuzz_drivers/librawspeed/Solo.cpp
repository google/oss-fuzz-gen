/*
    RawSpeed - RAW file decoder.

    Copyright (C) 2017-2023 Roman Lebedev

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

#include "adt/Casts.h"
#ifndef IMPL
#error IMPL must be defined to one of rawspeeds huffman table implementations
#endif

#include "codes/PrefixCodeDecoder.h" // IWYU pragma: keep
#include "codes/PrefixCodeDecoder/Common.h"
#include "codes/PrefixCodeLUTDecoder.h"    // IWYU pragma: keep
#include "codes/PrefixCodeLookupDecoder.h" // IWYU pragma: keep
#include "codes/PrefixCodeTreeDecoder.h"   // IWYU pragma: keep
#include "codes/PrefixCodeVectorDecoder.h" // IWYU pragma: keep
#include "common/RawspeedException.h"
#include "io/BitPumpJPEG.h"
#include "io/BitPumpMSB.h"
#include "io/BitPumpMSB32.h"
#include "io/Buffer.h"
#include "io/ByteStream.h"
#include "io/Endianness.h"
#include <cassert>
#include <cstdint>
#include <cstdio>

namespace rawspeed {
struct BaselineCodeTag;
struct VC5CodeTag;
} // namespace rawspeed

namespace {

template <typename Pump, bool IsFullDecode, typename HT> void workloop(rawspeed::ByteStream bs, const HT &ht) {
  Pump bits(bs.peekRemainingBuffer());
  while (true)
    ht.template decode<Pump, IsFullDecode>(bits);
  // FIXME: do we need to escape the result to avoid dead code elimination?
}

template <typename Pump, typename HT> void checkPump(rawspeed::ByteStream bs, const HT &ht) {
  if (ht.isFullDecode())
    workloop<Pump, /*IsFullDecode=*/true>(bs, ht);
  else
    workloop<Pump, /*IsFullDecode=*/false>(bs, ht);
}

template <typename CodeTag> void checkFlavour(rawspeed::ByteStream bs) {
#ifndef BACKIMPL
  const auto ht = createPrefixCodeDecoder<rawspeed::IMPL<CodeTag>>(bs);
#else
  const auto ht = createPrefixCodeDecoder<rawspeed::IMPL<CodeTag, rawspeed::BACKIMPL<CodeTag>>>(bs);
#endif

  // Which bit pump should we use?
  switch (bs.getByte()) {
  case 0:
    checkPump<rawspeed::BitPumpMSB>(bs, ht);
    break;
  case 1:
    checkPump<rawspeed::BitPumpMSB32>(bs, ht);
    break;
  case 2:
    checkPump<rawspeed::BitPumpJPEG>(bs, ht);
    break;
  default:
    ThrowRSE("Unknown bit pump");
  }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  assert(Data);

  try {
    const rawspeed::Buffer b(Data, rawspeed::implicit_cast<rawspeed::Buffer::size_type>(Size));
    const rawspeed::DataBuffer db(b, rawspeed::Endianness::little);
    rawspeed::ByteStream bs(db);

    // Which flavor?
    switch (bs.getByte()) {
    case 0:
      checkFlavour<rawspeed::BaselineCodeTag>(bs);
      break;
    case 1:
      checkFlavour<rawspeed::VC5CodeTag>(bs);
      break;
    default:
      ThrowRSE("Unknown flavor");
    }
  } catch (const rawspeed::RawspeedException &) {
    return 0;
  }

  __builtin_unreachable();
}
