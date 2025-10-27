/*
 * Copyright 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include <memory>

#include "ultrahdr/jpegr.h"

using namespace ultrahdr;

// Transfer functions for image data, sync with ultrahdr.h
const int kOfMin = ULTRAHDR_OUTPUT_UNSPECIFIED + 1;
const int kOfMax = ULTRAHDR_OUTPUT_MAX;

class UltraHdrDecFuzzer {
public:
  UltraHdrDecFuzzer(const uint8_t *data, size_t size) : mFdp(data, size) {};
  void process();

private:
  FuzzedDataProvider mFdp;
};

void UltraHdrDecFuzzer::process() {
  // hdr_of
  auto of = static_cast<ultrahdr_output_format>(mFdp.ConsumeIntegralInRange<int>(kOfMin, kOfMax));
  auto buffer = mFdp.ConsumeRemainingBytes<uint8_t>();
  jpegr_compressed_struct jpegImgR{buffer.data(), (int)buffer.size(), (int)buffer.size(), ULTRAHDR_COLORGAMUT_UNSPECIFIED};

  jpegr_info_struct info{};
  JpegR jpegHdr;
  (void)jpegHdr.getJPEGRInfo(&jpegImgR, &info);
// #define DUMP_PARAM
#ifdef DUMP_PARAM
  std::cout << "input buffer size " << jpegImgR.length << std::endl;
  std::cout << "image dimensions " << info.width << " x " << info.width << std::endl;
#endif
  if (info.width > kMaxWidth || info.height > kMaxHeight)
    return;
  size_t outSize = info.width * info.height * ((of == ULTRAHDR_OUTPUT_HDR_LINEAR) ? 8 : 4);
  jpegr_uncompressed_struct decodedJpegR;
  auto decodedRaw = std::make_unique<uint8_t[]>(outSize);
  decodedJpegR.data = decodedRaw.get();
  ultrahdr_metadata_struct metadata;
  (void)jpegHdr.decodeJPEGR(&jpegImgR, &decodedJpegR, mFdp.ConsumeFloatingPointInRange<float>(1.0, FLT_MAX), nullptr, of, nullptr, &metadata);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  UltraHdrDecFuzzer fuzzHandle(data, size);
  fuzzHandle.process();
  return 0;
}
