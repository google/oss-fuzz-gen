/*
    RawSpeed - RAW file decoder.

    Copyright (C) 2022 Roman Lebedev

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

#include "common/DngOpcodes.h"
#include "MemorySanitizer.h"
#include "adt/Array2DRef.h"
#include "adt/Casts.h"
#include "adt/Point.h"
#include "common/RawImage.h"
#include "fuzz/Common.h"
#include "io/Buffer.h"
#include "io/ByteStream.h"
#include "io/Endianness.h"
#include "io/IOException.h"
#include "metadata/ColorFilterArray.h"
#include <cassert>
#include <cstdint>
#include <cstdio>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  assert(Data);

  try {
    const rawspeed::Buffer b(Data, rawspeed::implicit_cast<rawspeed::Buffer::size_type>(Size));
    const rawspeed::DataBuffer db(b, rawspeed::Endianness::little);
    rawspeed::ByteStream bs(db);

    rawspeed::RawImage mRaw(CreateRawImage(bs));

    // Performance cut-off: don't bother with too large images.
    if (!mRaw->getUncroppedDim().hasPositiveArea() || mRaw->getUncroppedDim().area() > 1'000'000)
      ThrowIOE("Bad image size.");

    if (mRaw->isCFA)
      mRaw->cfa = CreateCFA(bs);

    mRaw->createData();
    switch (mRaw->getDataType()) {
    case rawspeed::RawImageType::UINT16: {
      rawspeed::Array2DRef<uint16_t> img = mRaw->getU16DataAsUncroppedArray2DRef();
      const uint16_t fill = bs.getU16();
      for (auto row = 0; row < img.height; ++row) {
        for (auto col = 0; col < img.width; ++col) {
          img(row, col) = fill;
        }
      }
      break;
    }
    case rawspeed::RawImageType::F32: {
      rawspeed::Array2DRef<float> img = mRaw->getF32DataAsUncroppedArray2DRef();
      const float fill = bs.getFloat();
      for (auto row = 0; row < img.height; ++row) {
        for (auto col = 0; col < img.width; ++col) {
          img(row, col) = fill;
        }
      }
      break;
    }
    }

    if (bs.getByte()) {
      rawspeed::iRectangle2D fullFrame({0, 0}, mRaw->getUncroppedDim());

      int crop_pos_col = bs.getI32();
      int crop_pos_row = bs.getI32();
      int cropped_width = bs.getI32();
      int cropped_height = bs.getI32();
      rawspeed::iRectangle2D subFrame(crop_pos_col, crop_pos_row, cropped_width, cropped_height);
      mRaw->subFrame(subFrame);
    }

    rawspeed::DngOpcodes codes(mRaw, bs.getSubStream(/*offset=*/0));
    codes.applyOpCodes(mRaw);
    rawspeed::MSan::CheckMemIsInitialized(mRaw->getByteDataAsUncroppedArray2DRef());

    mRaw->transferBadPixelsToMap();
  } catch (const rawspeed::RawspeedException &) { // NOLINT(bugprone-empty-catch)
    // Exceptions are good, crashes are bad.
  }

  return 0;
}
