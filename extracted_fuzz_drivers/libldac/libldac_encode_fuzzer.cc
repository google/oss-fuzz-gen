// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ldacBT.h"
#include <stddef.h>
#include <stdint.h>

#include <functional>
#include <fuzzer/FuzzedDataProvider.h>
#include <vector>

constexpr LDACBT_SMPL_FMT_T kFormat[] = {LDACBT_SMPL_FMT_S16, LDACBT_SMPL_FMT_S24, LDACBT_SMPL_FMT_S32, LDACBT_SMPL_FMT_F32};
constexpr int32_t kEqmidValue[] = {LDACBT_EQMID_HQ, LDACBT_EQMID_SQ, LDACBT_EQMID_MQ};
constexpr int32_t kChannel[] = {LDACBT_CHANNEL_MODE_STEREO, LDACBT_CHANNEL_MODE_DUAL_CHANNEL, LDACBT_CHANNEL_MODE_MONO};
constexpr int32_t kSamplingFrequency[] = {44100, 48000, 2 * 44100, 2 * 48000};
constexpr int32_t kLdacBtRequiredMtu = 679;
constexpr int32_t kMaxWlValue = 4;
constexpr int32_t kMinChValue = 1;
constexpr int32_t kMaxChValue = 2;
constexpr int32_t kOutputSize = 1024;

class Codec {
public:
  Codec(const uint8_t *data, size_t size) : mFdp(data, size){};
  ~Codec() { deInitEncoder(); }
  bool initEncoder();
  void deInitEncoder();
  void encodeFrames(const uint8_t *data, size_t size);
  void getSamplingFrequeny();
  void getBitrate();
  void getVersion();
  FuzzedDataProvider mFdp;

private:
  int32_t mChannel;
  LDACBT_SMPL_FMT_T mFormat;
  HANDLE_LDAC_BT mHandleLdacBt;
};

bool Codec::initEncoder() {
  mHandleLdacBt = ldacBT_get_handle();

  mChannel = mFdp.PickValueInArray(kChannel);
  mFormat = mFdp.PickValueInArray(kFormat);
  int32_t status = ldacBT_init_handle_encode(mHandleLdacBt, kLdacBtRequiredMtu, mFdp.PickValueInArray(kEqmidValue), mChannel, mFormat, mFdp.PickValueInArray(kSamplingFrequency));
  if (!status) {
    return true;
  }
  return false;
}

void Codec::encodeFrames(const uint8_t *data, size_t size) {
  int32_t pcmUsed, streamSize, frameNum;
  unsigned char pStream[kOutputSize];
  int32_t ch, wl, frameSize;
  ch = (mChannel == LDAC_CCI_MONO) ? kMinChValue : kMaxChValue;
  wl = mFormat > kMaxWlValue ? kMaxWlValue : mFormat;
  frameSize = LDACBT_ENC_LSU * ch * wl;
  std::vector<uint8_t> tmpData(frameSize);
  uint8_t *readPointer = const_cast<uint8_t *>(data);
  while (size > 0) {
    if (size < frameSize) {
      memcpy(tmpData.data(), data, size);
      size = frameSize;
      readPointer = tmpData.data();
    }
    ldacBT_encode(mHandleLdacBt, readPointer, &pcmUsed, pStream, &streamSize, &frameNum);
    readPointer += frameSize;
    size -= frameSize;
  }
}

void Codec::getSamplingFrequeny() { ldacBT_get_sampling_freq(mHandleLdacBt); }

void Codec::getBitrate() { ldacBT_get_bitrate(mHandleLdacBt); }

void Codec::getVersion() { ldacBT_get_version(); }

void Codec::deInitEncoder() {
  ldacBT_close_handle(mHandleLdacBt);
  ldacBT_free_handle(mHandleLdacBt);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t size) {
  Codec codec(buf, size);
  /* initEncoder() initializes mHandleLdacBt and is supposed to be called before
     encoding begins. Hence initEncoder() is not included in the lambda
     construct. */
  if (codec.initEncoder()) {
    while (codec.mFdp.remaining_bytes() > 0) {
      auto executeFunction = codec.mFdp.PickValueInArray<const std::function<void()>>({
          [&]() { codec.encodeFrames(buf, size); },
          [&]() { codec.getSamplingFrequeny(); },
          [&]() { codec.getBitrate(); },
          [&]() { codec.getVersion(); },
      });
      executeFunction();
    }
  }
  return 0;
}
