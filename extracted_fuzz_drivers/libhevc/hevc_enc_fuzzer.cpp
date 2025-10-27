/******************************************************************************
 *
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *****************************************************************************
 * Originally developed and contributed by Ittiam Systems Pvt. Ltd, Bangalore
 */
#include <algorithm>
#include <memory>
#include <string.h>

#include "ihevc_typedefs.h"
#include "ihevce_api.h"
#include "ihevce_plugin.h"
#include "ihevce_profile.h"
#include "itt_video_api.h"

#define NELEMENTS(x) (sizeof(x) / sizeof(x[0]))
constexpr size_t kRcType[] = {2, 3, 5};
constexpr IHEVCE_QUALITY_CONFIG_T kQuality[] = {IHEVCE_QUALITY_P0, IHEVCE_QUALITY_P2, IHEVCE_QUALITY_P3, IHEVCE_QUALITY_P4, IHEVCE_QUALITY_P5, IHEVCE_QUALITY_P6, IHEVCE_QUALITY_P7};

constexpr size_t kRcTypeNum = NELEMENTS(kRcType);
constexpr size_t kQualityNum = NELEMENTS(kQuality);
constexpr size_t kMaxQP = 51;
constexpr size_t kMaxGopPeriod = 16;
constexpr size_t kMaxWidth = 10240;
constexpr size_t kMaxHeight = 10240;
constexpr size_t kMaxBitrate = 500000000;

enum { IDX_WD_BYTE_1, IDX_WD_BYTE_2, IDX_HT_BYTE_1, IDX_HT_BYTE_2, IDX_MAX_INTRA_TX_DEPTH, IDX_MAX_INTER_TX_DEPTH, IDX_CU_RC, IDX_RC_MODE, IDX_FRAME_QP, IDX_PRESET, IDX_BITRATE_BYTE_1, IDX_BITRATE_BYTE_2, IDX_ENABLE_ENTROPY_SYNC, IDX_DEBLOCKING_TYPE, IDX_USE_SC_MTX, IDX_MAX_TEMPORAL_LAYERS, IDX_MAX_CLOSED_GOP, IDX_MIN_CLOSED_GOP, IDX_MAX_I_OPEN_GOP, IDX_MAX_CRA_OPEN_GOP, IDX_ENABLE_SPS_AT_CDR, IDX_ENABLE_VUI, IDX_ENABLE_SEI, IDX_ARCH_TYPE, IDX_ENABLE_FORCE_IDR, IDX_ENABLE_DYNAMIC_BITRATE, IDX_FORCE_IDR_INTERVAL, IDX_DYNAMIC_BITRATE_INTERVAL, IDX_LAST };

class Codec {
public:
  Codec() = default;
  ~Codec() { deInitEncoder(); }
  bool initEncoder(const uint8_t *data);
  void deInitEncoder();
  void encodeFrames(const uint8_t *data, size_t size);

private:
  bool mIsForceIdrEnabled = false;
  bool mIsDynamicBitrateChangeEnabled = false;
  size_t mWidth = 352;
  size_t mHeight = 288;
  size_t mForceIdrInterval = 0;       // in number of frames
  size_t mDynamicBitrateInterval = 0; // in number of frames
  uint64_t mBitrate = 5000000;
  void *mCodecCtx = nullptr;
  ihevce_static_cfg_params_t mEncParams = {};
};

bool Codec::initEncoder(const uint8_t *data) {
  // default configuration
  if (IHEVCE_EOK != ihevce_set_def_params(&mEncParams)) {
    return false;
  }
  mWidth = ((data[IDX_WD_BYTE_1] << 8) | data[IDX_WD_BYTE_2]) % kMaxWidth;
  mHeight = ((data[IDX_HT_BYTE_1] << 8) | data[IDX_HT_BYTE_2]) % kMaxHeight;

  // update configuration
  mEncParams.s_src_prms.i4_width = mWidth;
  mEncParams.s_src_prms.i4_height = mHeight;

  mEncParams.s_config_prms.i4_max_tr_tree_depth_I = (data[IDX_MAX_INTRA_TX_DEPTH] % 3) + 1;
  mEncParams.s_config_prms.i4_max_tr_tree_depth_nI = (data[IDX_MAX_INTER_TX_DEPTH] & 0x03) + 1;
  mEncParams.s_config_prms.i4_cu_level_rc = data[IDX_CU_RC] & 0x01;
  mEncParams.s_config_prms.i4_rate_control_mode = kRcType[data[IDX_RC_MODE] % kRcTypeNum];

  mEncParams.s_tgt_lyr_prms.as_tgt_params[0].ai4_frame_qp[0] = (data[IDX_FRAME_QP] % kMaxQP) + 1;
  mEncParams.s_tgt_lyr_prms.as_tgt_params[0].i4_quality_preset = kQuality[data[IDX_PRESET] % kQualityNum];
  mEncParams.s_tgt_lyr_prms.as_tgt_params[0].ai4_tgt_bitrate[0] = (((data[IDX_BITRATE_BYTE_1] << 8) | data[IDX_BITRATE_BYTE_2]) * 1000) % kMaxBitrate;
  mEncParams.s_tgt_lyr_prms.as_tgt_params[0].ai4_peak_bitrate[0] = ((((data[IDX_BITRATE_BYTE_1] << 8) | data[IDX_BITRATE_BYTE_2]) * 1000) % kMaxBitrate) << 1;
  mEncParams.s_coding_tools_prms.i4_enable_entropy_sync = data[IDX_ENABLE_ENTROPY_SYNC] & 0x01;
  mEncParams.s_coding_tools_prms.i4_deblocking_type = data[IDX_DEBLOCKING_TYPE] & 0x01;
  mEncParams.s_coding_tools_prms.i4_use_default_sc_mtx = data[IDX_USE_SC_MTX] & 0x01;
  mEncParams.s_coding_tools_prms.i4_max_temporal_layers = data[IDX_MAX_TEMPORAL_LAYERS] & 0x02;
  mEncParams.s_coding_tools_prms.i4_max_closed_gop_period = data[IDX_MAX_CLOSED_GOP] % kMaxGopPeriod;
  mEncParams.s_coding_tools_prms.i4_min_closed_gop_period = data[IDX_MIN_CLOSED_GOP] % kMaxGopPeriod;
  mEncParams.s_coding_tools_prms.i4_max_i_open_gop_period = data[IDX_MAX_I_OPEN_GOP] % kMaxGopPeriod;
  mEncParams.s_coding_tools_prms.i4_max_cra_open_gop_period = data[IDX_MAX_CRA_OPEN_GOP] % kMaxGopPeriod;

  mEncParams.s_out_strm_prms.i4_sps_at_cdr_enable = data[IDX_ENABLE_SPS_AT_CDR] & 0x01;
  mEncParams.s_out_strm_prms.i4_vui_enable = data[IDX_ENABLE_VUI] & 0x01;
  mEncParams.s_out_strm_prms.i4_sei_enable_flag = data[IDX_ENABLE_SEI] & 0x01;

  mEncParams.e_arch_type = ((data[IDX_ARCH_TYPE] & 0x03) == 0x00) ? ARCH_ARM_NONEON : ARCH_NA;
  mIsForceIdrEnabled = data[IDX_ENABLE_FORCE_IDR] & 0x01;
  mIsDynamicBitrateChangeEnabled = data[IDX_ENABLE_DYNAMIC_BITRATE] & 0x01;
  mForceIdrInterval = data[IDX_FORCE_IDR_INTERVAL] & 0x07;
  mDynamicBitrateInterval = data[IDX_DYNAMIC_BITRATE_INTERVAL] & 0x07;

  if (IHEVCE_EOK != ihevce_init(&mEncParams, &mCodecCtx)) {
    return false;
  }
  return true;
}

void Codec::encodeFrames(const uint8_t *data, size_t size) {
  size_t frameSize = (mWidth * mHeight * 3) / 2;

  ihevce_out_buf_t sHeaderOp{};
  ihevce_encode_header(mCodecCtx, &sHeaderOp);
  size_t frameNumber = 0;
  uint8_t *tmpData = new uint8_t[frameSize];
  while (size > 0) {
    ihevce_inp_buf_t sEncodeIp{};
    ihevce_out_buf_t sEncodeOp{};
    size_t bytesConsumed = std::min(size, frameSize);
    if (bytesConsumed < frameSize) {
      memset(&tmpData[bytesConsumed], data[0], frameSize - bytesConsumed);
    }
    memcpy(tmpData, data, bytesConsumed);
    int32_t yStride = mWidth;
    int32_t uStride = mWidth >> 1;
    int32_t vStride = mWidth >> 1;

    sEncodeIp.apv_inp_planes[0] = tmpData;
    sEncodeIp.apv_inp_planes[1] = tmpData + (mWidth * mHeight);
    sEncodeIp.apv_inp_planes[2] = tmpData + ((mWidth * mHeight) * 5) / 4;

    sEncodeIp.ai4_inp_strd[0] = yStride;
    sEncodeIp.ai4_inp_strd[1] = uStride;
    sEncodeIp.ai4_inp_strd[2] = vStride;

    sEncodeIp.ai4_inp_size[0] = yStride * mHeight;
    sEncodeIp.ai4_inp_size[1] = uStride * mHeight >> 1;
    sEncodeIp.ai4_inp_size[2] = vStride * mHeight >> 1;

    sEncodeIp.i4_force_idr_flag = 0;
    sEncodeIp.i4_curr_bitrate = mBitrate;
    sEncodeIp.i4_curr_peak_bitrate = mBitrate << 1;
    sEncodeIp.u8_pts = 0;
    if (mIsForceIdrEnabled) {
      if (frameNumber == mForceIdrInterval) {
        sEncodeIp.i4_force_idr_flag = 1;
      }
    }
    if (mIsDynamicBitrateChangeEnabled) {
      if (frameNumber == mDynamicBitrateInterval) {
        mBitrate = mBitrate << 1;
      }
    }
    ihevce_encode(mCodecCtx, &sEncodeIp, &sEncodeOp);
    ++frameNumber;
    data += bytesConsumed;
    size -= bytesConsumed;
  }
  delete[] tmpData;
}

void Codec::deInitEncoder() {
  if (mCodecCtx) {
    ihevce_close(mCodecCtx);
    mCodecCtx = nullptr;
  }
  return;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < IDX_LAST) {
    return 0;
  }
  Codec *codec = new Codec();
  if (codec->initEncoder(data)) {
    data += IDX_LAST;
    size -= IDX_LAST;
    codec->encodeFrames(data, size);
  }
  delete codec;
  return 0;
}
