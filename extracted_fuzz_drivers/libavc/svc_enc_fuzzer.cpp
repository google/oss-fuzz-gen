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
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <numeric>
#include <utility>
#include <vector>

#include "ih264_typedefs.h"
#include "isvce.h"
#include "iv2.h"
#include "ive2.h"

constexpr WORD32 kMeSpeedPreset[] = {100};
constexpr WORD32 kDeblkLevel[] = {0, 2, 3, 4};
constexpr IVE_AIR_MODE_T kAirMode[] = {IVE_AIR_MODE_NONE};
constexpr IVE_SPEED_CONFIG kEncSpeed[] = {IVE_CONFIG, IVE_SLOWEST, IVE_NORMAL, IVE_FAST, IVE_HIGH_SPEED, IVE_FASTEST};
constexpr IV_PROFILE_T kProfile[] = {IV_PROFILE_BASE, IV_PROFILE_MAIN};
constexpr IVE_RC_MODE_T kRCMode[] = {IVE_RC_NONE, IVE_RC_STORAGE, IVE_RC_CBR_NON_LOW_DELAY, IVE_RC_CBR_LOW_DELAY};
constexpr IV_COLOR_FORMAT_T kSupportedColorFormats[] = {IV_YUV_420P, IV_YUV_420SP_UV};
constexpr WORD32 kSupportedLevels[] = {10, 9, 11, 12, 13, 20, 21, 22, 30, 31, 32, 40, 41, 42, 50, 51};
constexpr IVE_SLICE_MODE_T kSliceMode[] = {IVE_SLICE_MODE_NONE};
constexpr IV_ARCH_T kArchs[] = {ARCH_ARM_NONEON, ARCH_ARM_A9Q, ARCH_ARM_A9A, ARCH_ARM_A9, ARCH_ARM_A7, ARCH_ARM_A5, ARCH_ARM_A15, ARCH_ARM_NEONINTR, ARCH_X86_GENERIC, ARCH_X86_SSSE3, ARCH_X86_SSE42, ARCH_ARM_A53, ARCH_ARM_A57, ARCH_ARM_V8_NEON};
constexpr DOUBLE kSpatialResRatio[] = {1.5, 2};
constexpr UWORD8 kSpatialLayers[] = {1, 2, 3};
constexpr UWORD8 kTemporalLayers[] = {1, 2, 3};
constexpr size_t kAirModeNum = std::size(kAirMode);
constexpr size_t kEncSpeedNum = std::size(kEncSpeed);
constexpr size_t kMeSpeedPresetNum = std::size(kMeSpeedPreset);
constexpr size_t kDeblkLevelNum = std::size(kDeblkLevel);
constexpr size_t kProfileNum = std::size(kProfile);
constexpr size_t kRCModeNum = std::size(kRCMode);
constexpr size_t kSupportedColorFormatsNum = std::size(kSupportedColorFormats);
constexpr size_t kSupportedLevelsNum = std::size(kSupportedLevels);
constexpr size_t kSliceModeNum = std::size(kSliceMode);
constexpr size_t kSpatialResRatioNum = std::size(kSpatialResRatio);
constexpr size_t kSpatialLayersNum = std::size(kSpatialLayers);
constexpr size_t kTemporalLayersNum = std::size(kTemporalLayers);
constexpr size_t kMinQP = 0;
constexpr size_t kMaxQP = 51;
constexpr size_t kMaxWidth = 2560;
constexpr size_t kMaxHeight = 2560;
constexpr size_t kMaxBitrate = 500000000;
constexpr UWORD8 kNumSeiMdcvPrimaries = 3;
constexpr UWORD8 kNumSeiCcvPrimaries = 3;
constexpr double kSvcCompliantDimProb = 0.75;
constexpr size_t kMaxEncodeCalls = 100;

typedef enum ARG_INDICES_T {
  IDX_WD_BYTE_1,
  IDX_WD_BYTE_2,
  IDX_HT_BYTE_1,
  IDX_HT_BYTE_2,
  IDX_COLOR_FORMAT,
  IDX_ARCH_TYPE,
  IDX_RC_MODE,
  IDX_NUM_CORES,
  IDX_NUM_ARCH,
  IDX_NUM_B_FRAMES,
  IDX_ENC_SPEED,
  IDX_CONSTRAINED_INTRA_FLAG,
  IDX_INTRA_4x4,
  IDX_I_FRAME_QP,
  IDX_P_FRAME_QP,
  IDX_B_FRAME_QP,
  IDX_BITRATE_BYTE_1,
  IDX_BITRATE_BYTE_2,
  IDX_FRAME_RATE,
  IDX_INTRA_REFRESH,
  IDX_ENABLE_HALF_PEL,
  IDX_ENABLE_Q_PEL,
  IDX_ME_SPEED_PRESET,
  IDX_AIR_MODE,
  IDX_DISABLE_DEBLOCK_LEVEL,
  IDX_SEARCH_RANGE_X,
  IDX_SEARCH_RANGE_Y,
  IDX_I_INTERVAL,
  IDX_IDR_INTERVAL,
  IDX_SEI_MDCV_FLAG,
  IDX_SEI_CLL_FLAG,
  IDX_SEI_AVE_FLAG,
  IDX_SEI_CCV_FLAG,
  IDX_PROFILE,
  IDX_ASPECT_RATIO_FLAG,
  IDX_NAL_HRD_FLAG,
  IDX_VCL_HRD_FLAG,
  IDX_ENABLE_FORCE_IDR,
  IDX_ENABLE_DYNAMIC_BITRATE,
  IDX_ENABLE_DYNAMIC_FRAME_RATE,
  IDX_FORCE_IDR_INTERVAL,
  IDX_DYNAMIC_BITRATE_INTERVAL,
  IDX_DYNAMIC_FRAME_RATE_INTERVAL,
  IDX_ENC_LEVEL,
  IDX_RECON_FMT,
  IDX_SLICE_MODE,
  IDX_ENABLE_FAST_SAD,
  IDX_NUM_SPATIAL_LAYERS,
  IDX_NUM_TEMPORAL_LAYERS,
  IDX_SPATIAL_RES_RATIO,
  IDX_SVC_COMPLIANT_DIMS,
  IDX_ENABLE_RECON,
  IDX_ENABLE_NALU_INFO_EXPORT,
  IDX_LAST
} ARG_INDICES_T;

class Codec {
public:
  struct FrameDims {
    size_t mWidth;
    size_t mHeight;

    FrameDims(size_t w, size_t h) : mWidth(w), mHeight(h) {}
    FrameDims(const std::pair<size_t, size_t> &dimPair) : FrameDims(dimPair.first, dimPair.second) {}
    FrameDims(const FrameDims &other) : FrameDims(other.mWidth, other.mHeight) {}

    void operator=(const FrameDims &other) {
      mWidth = other.mWidth;
      mHeight = other.mHeight;
    }

    size_t getFrameSize() const { return (mWidth * mHeight * 3) / 2; };
  };

  struct EncBufs {
    std::vector<UWORD8> mInputBuf;
    std::vector<UWORD8> mOutputBuf;
    std::vector<UWORD8> mReconBuf;
    std::vector<isvce_nalu_info_buf_t> mNaluInfoStructBuf;
    std::vector<std::vector<UWORD8>> mNaluInfoDataBuf;
  };

  Codec()
      : mCodecCtx(nullptr), mMemRecords(), mMemRecBufs(), mEncBufs(), mAirMode(IVE_AIR_MODE_NONE), mEncSpeed(IVE_NORMAL), mRCMode(IVE_RC_NONE), mArch(ARCH_NA), mSliceMode(IVE_SLICE_MODE_NONE), mIvVideoColorFormat(IV_YUV_420P), mProfile(IV_PROFILE_BASE), mSvcCompDims{kMaxWidth, kMaxHeight}, mInputDims{kMaxWidth, kMaxHeight}, mHalfPelEnable(1), mQPelEnable(1), mIntra4x4(0), mEnableFastSad(0), mEnableAltRef(0), mConstrainedIntraFlag(0), mSeiCllFlag(1), mSeiAveFlag(1), mSeiCcvFlag(1), mSeiMdcvFlag(1), mAspectRatioFlag(0), mNalHrdFlag(0), mVclHrdFlag(0), mIsForceIdrEnabled(false), mIsDynamicBitRateChangeEnabled(false), mIsDynamicFrameRateChangeEnabled(false), mEnableRecon(false), mEnableNaluInfoExport(false), mAvcEncLevel(41), mNumMemRecords(0), mNumCores(1), mBframes(0), mSliceParam(256), mMeSpeedPreset(100), mIInterval(60), mIDRInterval(60), mDisableDeblockLevel(0), m_I_QP(22), m_P_QP(28), m_B_QP(22), mIntraRefresh(30), mSearchRangeX(64), mSearchRangeY(48), mForceIdrInterval(0),
        mDynamicBitRateInterval(0), mDynamicFrameRateInterval(0), mBitrate(6000000), mFrameRate(30), mNumSpatialLayers(1), mNumTemporalLayers(1), mSpatialResRatio(2) {}

  ~Codec() { delMemRecs(); };

  bool initEncoder(const UWORD8 *data);
  bool encodeFrames(const UWORD8 *data, size_t size);

private:
  void setEncParams(iv_raw_buf_t *psInpRawBuf, std::vector<UWORD8> &buf, const FrameDims &dims, IV_COLOR_FORMAT_T colorFormat = IV_YUV_420P);
  void setFrameType(IV_PICTURE_CODING_TYPE_T eFrameType);
  void setQp();
  void setEncMode(IVE_ENC_MODE_T eEncMode);
  void setDimensions();
  void setNumCores();
  void setFrameRate();
  void setIpeParams();
  void setBitRate();
  void setAirParams();
  void setMeParams();
  void setGopParams();
  void setProfileParams();
  void setDeblockParams();
  void setVbvParams();
  void setDefault();
  void setVuiParams();
  void getBufInfo();
  void setSeiMdcvParams();
  void setSeiCllParams();
  void setSeiAveParams();
  void setSeiCcvParams();
  void logVersion();
  void initEncBufs();
  bool initMemRecs();
  void delMemRecs();

  iv_obj_t *mCodecCtx;
  std::vector<iv_mem_rec_t> mMemRecords;
  std::vector<UWORD8 *> mMemRecBufs;
  EncBufs mEncBufs;

  IVE_AIR_MODE_T mAirMode;
  IVE_SPEED_CONFIG mEncSpeed;
  IVE_RC_MODE_T mRCMode;
  IV_ARCH_T mArch;
  IVE_SLICE_MODE_T mSliceMode;
  IV_COLOR_FORMAT_T mIvVideoColorFormat;
  IV_PROFILE_T mProfile;
  FrameDims mSvcCompDims;
  FrameDims mInputDims;

  bool mHalfPelEnable;
  bool mQPelEnable;
  bool mIntra4x4;
  bool mEnableFastSad;
  bool mEnableAltRef;
  bool mConstrainedIntraFlag;
  bool mSeiCllFlag;
  bool mSeiAveFlag;
  bool mSeiCcvFlag;
  bool mSeiMdcvFlag;
  bool mAspectRatioFlag;
  bool mNalHrdFlag;
  bool mVclHrdFlag;
  bool mIsForceIdrEnabled;
  bool mIsDynamicBitRateChangeEnabled;
  bool mIsDynamicFrameRateChangeEnabled;
  bool mEnableRecon;
  bool mEnableNaluInfoExport;
  UWORD32 mAvcEncLevel;
  UWORD32 mNumMemRecords;
  UWORD32 mNumCores;
  UWORD32 mBframes;
  UWORD32 mSliceParam;
  UWORD32 mMeSpeedPreset;
  UWORD32 mIInterval;
  UWORD32 mIDRInterval;
  UWORD32 mDisableDeblockLevel;
  UWORD32 m_I_QP;
  UWORD32 m_P_QP;
  UWORD32 m_B_QP;
  UWORD32 mIntraRefresh;
  UWORD32 mSearchRangeX;
  UWORD32 mSearchRangeY;
  /* Units - number of frames */
  UWORD32 mForceIdrInterval;
  /* Units - number of frames */
  UWORD32 mDynamicBitRateInterval;
  /* Units - number of frames */
  UWORD32 mDynamicFrameRateInterval;
  UWORD64 mBitrate;
  DOUBLE mFrameRate;
  UWORD8 mNumSpatialLayers;
  UWORD8 mNumTemporalLayers;
  DOUBLE mSpatialResRatio;
};

void Codec::initEncBufs() {
  size_t frameSize = mInputDims.getFrameSize();
  constexpr size_t minOutBufSize = 0x800;
  size_t outBufSize = std::max(minOutBufSize, frameSize * mNumSpatialLayers);
  size_t naluInfoBufSize = 460 * mNumSpatialLayers;

  mEncBufs.mInputBuf.resize(frameSize);
  mEncBufs.mOutputBuf.resize(outBufSize);

  if (mEnableRecon) {
    mEncBufs.mReconBuf.resize(frameSize);
  }

  if (mEnableNaluInfoExport) {
    mEncBufs.mNaluInfoStructBuf.resize(mNumSpatialLayers * 2);
    mEncBufs.mNaluInfoDataBuf.resize(mNumSpatialLayers);

    for (auto i = 0; i < mNumSpatialLayers; i++) {
      mEncBufs.mNaluInfoDataBuf[i].resize(naluInfoBufSize);
    }
  }
}

bool Codec::initMemRecs() {
  std::fill(mMemRecBufs.begin(), mMemRecBufs.end(), nullptr);

  for (auto i = 0u; i < mNumMemRecords; i++) {
    mMemRecBufs[i] = reinterpret_cast<UWORD8 *>(aligned_alloc(mMemRecords[i].u4_mem_alignment, mMemRecords[i].u4_mem_size));
    mMemRecords[i].pv_base = mMemRecBufs[i];

    if (nullptr == mMemRecBufs[i]) {
      for (auto j = 0u; j < i; j++) {
        free(mMemRecBufs[j]);
      }

      return false;
    }
  }

  return true;
}

void Codec::delMemRecs() {
  for (auto i = 0u; i < mNumMemRecords; i++) {
    if (mMemRecBufs[i]) {
      free(mMemRecBufs[i]);
    }
  }

  std::fill(mMemRecBufs.begin(), mMemRecBufs.end(), nullptr);
}

bool Codec::initEncoder(const UWORD8 *data) {
  mInputDims = FrameDims{((data[IDX_WD_BYTE_1] << 8) | data[IDX_WD_BYTE_2]) % kMaxWidth, ((data[IDX_HT_BYTE_1] << 8) | data[IDX_HT_BYTE_2]) % kMaxHeight};

  mNumSpatialLayers = kSpatialLayers[data[IDX_NUM_SPATIAL_LAYERS] % kSpatialLayersNum];
  mNumTemporalLayers = kTemporalLayers[data[IDX_NUM_TEMPORAL_LAYERS] % kTemporalLayersNum];
  mSpatialResRatio = kSpatialResRatio[data[IDX_SPATIAL_RES_RATIO] % kSpatialResRatioNum];
  bool useSvcCompliantDims = data[IDX_SVC_COMPLIANT_DIMS] < static_cast<UWORD8>(std::numeric_limits<UWORD8>::max() * kSvcCompliantDimProb);

  if (useSvcCompliantDims) {
    auto getSvcCompliantDims = [&]() -> FrameDims {
      auto maxResRatio = pow(mSpatialResRatio, mNumSpatialLayers - 1);
      UWORD32 dimPadding = 0;
      UWORD32 numDecimalDigits = mNumSpatialLayers;
      constexpr auto minDimGcd = 16;
      UWORD32 decPtDelMultiplier = static_cast<UWORD32>(std::pow(10, numDecimalDigits));
      FrameDims dims{mInputDims};

      if (std::fmod(minDimGcd, maxResRatio)) {
        dimPadding = std::lcm(minDimGcd * decPtDelMultiplier, static_cast<UWORD32>(maxResRatio * decPtDelMultiplier)) / decPtDelMultiplier;
      } else {
        dimPadding = static_cast<UWORD32>(minDimGcd * maxResRatio);
      }

      if (mInputDims.mWidth % dimPadding) {
        dims.mWidth = mInputDims.mWidth - ((mInputDims.mWidth) % dimPadding) + dimPadding;
      }

      if (mInputDims.mHeight % dimPadding) {
        dims.mHeight = mInputDims.mHeight - ((mInputDims.mHeight) % dimPadding) + dimPadding;
      }

      return dims;
    };

    mSvcCompDims = getSvcCompliantDims();
    mInputDims = mSvcCompDims;
  }

  mIvVideoColorFormat = kSupportedColorFormats[data[IDX_COLOR_FORMAT] % kSupportedColorFormatsNum];
  mArch = kArchs[data[IDX_ARCH_TYPE] % std::size(kArchs)];
  mRCMode = kRCMode[data[IDX_RC_MODE] % kRCModeNum];
  mNumCores = (data[IDX_NUM_CORES] & 0x07) + 1;
  mBframes = 0;

  mEncSpeed = kEncSpeed[data[IDX_ENC_SPEED] % kEncSpeedNum];
  mConstrainedIntraFlag = data[IDX_CONSTRAINED_INTRA_FLAG] & 0x01;
  mIntra4x4 = data[IDX_INTRA_4x4] & 0x01;
  m_I_QP = data[IDX_I_FRAME_QP];
  m_P_QP = data[IDX_P_FRAME_QP];
  m_B_QP = data[IDX_B_FRAME_QP];
  mBitrate = (((data[IDX_BITRATE_BYTE_1] << 8) | data[IDX_BITRATE_BYTE_2]) * 1000) % kMaxBitrate;
  mFrameRate = data[IDX_FRAME_RATE] % 120;
  mIntraRefresh = data[IDX_INTRA_REFRESH] + 1;
  mHalfPelEnable = data[IDX_ENABLE_HALF_PEL] & 0x01;
  mQPelEnable = data[IDX_ENABLE_Q_PEL] & 0x01;
  mMeSpeedPreset = kMeSpeedPreset[data[IDX_ME_SPEED_PRESET] % kMeSpeedPresetNum];
  mAirMode = kAirMode[data[IDX_AIR_MODE] % kAirModeNum];
  mDisableDeblockLevel = kDeblkLevel[data[IDX_DISABLE_DEBLOCK_LEVEL] % kDeblkLevelNum];
  mSearchRangeX = data[IDX_SEARCH_RANGE_X];
  mSearchRangeY = data[IDX_SEARCH_RANGE_Y];
  mIInterval = data[IDX_I_INTERVAL] + 1;
  mIDRInterval = data[IDX_IDR_INTERVAL] + 1;
  mSeiMdcvFlag = data[IDX_SEI_MDCV_FLAG] & 0x01;
  mSeiCllFlag = data[IDX_SEI_CLL_FLAG] & 0x01;
  mSeiAveFlag = data[IDX_SEI_AVE_FLAG] & 0x01;
  mSeiCcvFlag = data[IDX_SEI_CCV_FLAG] & 0x01;
  mProfile = kProfile[data[IDX_PROFILE] % kProfileNum];
  mAspectRatioFlag = data[IDX_ASPECT_RATIO_FLAG] & 0x01;
  mNalHrdFlag = data[IDX_NAL_HRD_FLAG] & 0x01;
  mVclHrdFlag = data[IDX_VCL_HRD_FLAG] & 0x01;
  mIsForceIdrEnabled = data[IDX_ENABLE_FORCE_IDR] & 0x01;
  mIsDynamicBitRateChangeEnabled = data[IDX_ENABLE_DYNAMIC_BITRATE] & 0x01;
  mIsDynamicFrameRateChangeEnabled = data[IDX_ENABLE_DYNAMIC_FRAME_RATE] & 0x01;
  mForceIdrInterval = data[IDX_FORCE_IDR_INTERVAL] & 0x07;
  mDynamicBitRateInterval = data[IDX_DYNAMIC_BITRATE_INTERVAL] & 0x07;
  mDynamicFrameRateInterval = data[IDX_DYNAMIC_FRAME_RATE_INTERVAL] & 0x07;

  mSliceParam = std::min(256u, static_cast<UWORD32>(mInputDims.mHeight >> 4));
  mAvcEncLevel = kSupportedLevels[data[IDX_ENC_LEVEL] % kSupportedLevelsNum];
  mSliceMode = kSliceMode[data[IDX_SLICE_MODE] % kSliceModeNum];
  mEnableFastSad = data[IDX_ENABLE_FAST_SAD] & 0x01;

  mEnableRecon = !!(data[IDX_ENABLE_RECON] & 1);
  mEnableNaluInfoExport = !!(data[IDX_ENABLE_NALU_INFO_EXPORT] & 1);

  isvce_num_mem_rec_ip_t s_num_mem_rec_ip{};
  isvce_num_mem_rec_op_t s_num_mem_rec_op{};

  isvce_api_cmds_t s_api_cmds{ISVCE_CMD_GET_NUM_MEM_REC, ISVCE_CMD_CT_NA};

  /* Getting Number of MemRecords */
  s_num_mem_rec_ip.s_ive_ip.u4_size = sizeof(isvce_num_mem_rec_ip_t);
  s_num_mem_rec_op.s_ive_op.u4_size = sizeof(isvce_num_mem_rec_op_t);

  if (IV_SUCCESS != isvce_api_function(0, &s_num_mem_rec_ip, &s_num_mem_rec_op, &s_api_cmds)) {
    return false;
  }

  mNumMemRecords = s_num_mem_rec_op.s_ive_op.u4_num_mem_rec;
  mMemRecords.resize(mNumMemRecords);
  mMemRecBufs.resize(mNumMemRecords);

  for (auto i = 0u; i < mNumMemRecords; i++) {
    mMemRecords[i].u4_size = sizeof(iv_mem_rec_t);
    mMemRecords[i].pv_base = nullptr;
    mMemRecords[i].u4_mem_size = 0;
    mMemRecords[i].u4_mem_alignment = 0;
    mMemRecords[i].e_mem_type = IV_NA_MEM_TYPE;
  }

  isvce_fill_mem_rec_ip_t sFillMemRecIp{};
  isvce_fill_mem_rec_op_t sFillMemRecOp{};

  s_api_cmds = {ISVCE_CMD_FILL_NUM_MEM_REC, ISVCE_CMD_CT_NA};

  sFillMemRecIp.s_ive_ip.u4_size = sizeof(isvce_fill_mem_rec_ip_t);
  sFillMemRecOp.s_ive_op.u4_size = sizeof(isvce_fill_mem_rec_op_t);

  sFillMemRecIp.s_ive_ip.ps_mem_rec = mMemRecords.data();
  sFillMemRecIp.s_ive_ip.u4_num_mem_rec = mNumMemRecords;
  sFillMemRecIp.s_ive_ip.u4_max_wd = mInputDims.mWidth;
  sFillMemRecIp.s_ive_ip.u4_max_ht = mInputDims.mHeight;
  sFillMemRecIp.u4_wd = mInputDims.mWidth;
  sFillMemRecIp.u4_ht = mInputDims.mHeight;
  sFillMemRecIp.s_ive_ip.u4_max_level = mAvcEncLevel;
  sFillMemRecIp.s_ive_ip.e_color_format = mIvVideoColorFormat;
  sFillMemRecIp.s_ive_ip.u4_max_ref_cnt = 2;
  sFillMemRecIp.s_ive_ip.u4_max_reorder_cnt = 0;
  sFillMemRecIp.s_ive_ip.u4_max_srch_rng_x = 256;
  sFillMemRecIp.s_ive_ip.u4_max_srch_rng_y = 256;

  sFillMemRecIp.s_svc_inp_params.u1_num_temporal_layers = mNumTemporalLayers;
  sFillMemRecIp.s_svc_inp_params.u1_num_spatial_layers = mNumSpatialLayers;
  sFillMemRecIp.s_svc_inp_params.d_spatial_res_ratio = mSpatialResRatio;

  if (IV_SUCCESS != isvce_api_function(0, &sFillMemRecIp, &sFillMemRecOp, &s_api_cmds)) {
    return false;
  }

  if (!initMemRecs()) {
    return false;
  }

  /* Codec Instance Creation */
  isvce_init_ip_t sInitIp{};
  isvce_init_op_t sInitOp{};

  std::vector<UWORD32> sMaxBitrates(mNumSpatialLayers, 240000000);

  mCodecCtx = reinterpret_cast<iv_obj_t *>(mMemRecords[0].pv_base);
  mCodecCtx->u4_size = sizeof(iv_obj_t);
  mCodecCtx->pv_fxns = reinterpret_cast<void *>(isvce_api_function);

  sInitIp.s_ive_ip.u4_size = sizeof(isvce_init_ip_t);
  sInitOp.s_ive_op.u4_size = sizeof(isvce_init_op_t);

  s_api_cmds = {ISVCE_CMD_INIT, ISVCE_CMD_CT_NA};

  sInitIp.s_ive_ip.u4_num_mem_rec = mNumMemRecords;
  sInitIp.s_ive_ip.ps_mem_rec = mMemRecords.data();
  sInitIp.s_ive_ip.u4_max_wd = mInputDims.mWidth;
  sInitIp.s_ive_ip.u4_max_ht = mInputDims.mHeight;
  sInitIp.u4_wd = mInputDims.mWidth;
  sInitIp.u4_ht = mInputDims.mHeight;

  sInitIp.s_ive_ip.u4_max_ref_cnt = 2;
  sInitIp.s_ive_ip.u4_max_reorder_cnt = 0;
  sInitIp.s_ive_ip.u4_max_level = mAvcEncLevel;
  sInitIp.s_ive_ip.e_inp_color_fmt = mIvVideoColorFormat;

  sInitIp.s_ive_ip.u4_enable_recon = mEnableRecon;
  sInitIp.s_ive_ip.e_recon_color_fmt = IV_YUV_420P;
  sInitIp.b_nalu_info_export_enable = mEnableNaluInfoExport;
  sInitIp.s_ive_ip.e_rc_mode = mRCMode;
  sInitIp.s_ive_ip.u4_max_framerate = 120000;
  sInitIp.pu4_max_bitrate = sMaxBitrates.data();
  sInitIp.s_svc_inp_params.u1_num_temporal_layers = mNumTemporalLayers;
  sInitIp.s_svc_inp_params.u1_num_spatial_layers = mNumSpatialLayers;
  sInitIp.s_svc_inp_params.d_spatial_res_ratio = mSpatialResRatio;

  sInitIp.s_ive_ip.u4_num_bframes = mBframes;
  sInitIp.s_ive_ip.e_content_type = IV_PROGRESSIVE;
  sInitIp.s_ive_ip.u4_max_srch_rng_x = 256;
  sInitIp.s_ive_ip.u4_max_srch_rng_y = 256;
  sInitIp.s_ive_ip.e_slice_mode = mSliceMode;
  sInitIp.s_ive_ip.u4_slice_param = mSliceParam;
  sInitIp.s_ive_ip.e_arch = mArch;
  sInitIp.s_ive_ip.e_soc = SOC_GENERIC;
  sInitIp.b_use_default_vui = true;

  if (IV_SUCCESS != isvce_api_function(mCodecCtx, &sInitIp, &sInitOp, &s_api_cmds)) {
    delMemRecs();

    return false;
  }

  setDefault();
  setNumCores();
  logVersion();
  getBufInfo();
  setDimensions();
  setFrameRate();
  setIpeParams();
  setBitRate();
  setQp();
  setAirParams();
  setVbvParams();
  setMeParams();
  setGopParams();
  setDeblockParams();
  setProfileParams();
  setEncMode(IVE_ENC_MODE_HEADER);
  setVuiParams();
  setSeiMdcvParams();
  setSeiCllParams();
  setSeiAveParams();
  setSeiCcvParams();

  initEncBufs();

  return true;
}

void Codec::setDimensions() {
  isvce_ctl_set_dimensions_ip_t s_frame_dimensions_ip{};
  isvce_ctl_set_dimensions_op_t s_frame_dimensions_op{};

  isvce_api_cmds_t s_api_cmds{ISVCE_CMD_VIDEO_CTL, ISVCE_CMD_CTL_SET_DIMENSIONS};

  s_frame_dimensions_ip.s_ive_ip.u4_ht = mInputDims.mHeight;
  s_frame_dimensions_ip.s_ive_ip.u4_wd = mInputDims.mWidth;

  s_frame_dimensions_ip.s_ive_ip.u4_timestamp_high = 0;
  s_frame_dimensions_ip.s_ive_ip.u4_timestamp_low = 0;

  s_frame_dimensions_ip.s_ive_ip.u4_size = sizeof(isvce_ctl_set_dimensions_ip_t);
  s_frame_dimensions_op.s_ive_op.u4_size = sizeof(isvce_ctl_set_dimensions_op_t);

  isvce_api_function(mCodecCtx, &s_frame_dimensions_ip, &s_frame_dimensions_op, &s_api_cmds);
}

void Codec::setNumCores() {
  isvce_ctl_set_num_cores_ip_t sNumCoresIp{};
  isvce_ctl_set_num_cores_op_t sNumCoresOp{};

  isvce_api_cmds_t s_api_cmds{ISVCE_CMD_VIDEO_CTL, ISVCE_CMD_CTL_SET_NUM_CORES};

  sNumCoresIp.s_ive_ip.u4_num_cores = mNumCores;

  sNumCoresIp.s_ive_ip.u4_timestamp_high = 0;
  sNumCoresIp.s_ive_ip.u4_timestamp_low = 0;

  sNumCoresIp.s_ive_ip.u4_size = sizeof(isvce_ctl_set_num_cores_ip_t);
  sNumCoresOp.s_ive_op.u4_size = sizeof(isvce_ctl_set_num_cores_op_t);

  isvce_api_function(mCodecCtx, (void *)&sNumCoresIp, (void *)&sNumCoresOp, &s_api_cmds);
}

void Codec::setDefault() {
  isvce_ctl_setdefault_ip_t sDefaultIp{};
  isvce_ctl_setdefault_op_t sDefaultOp{};

  isvce_api_cmds_t s_api_cmds{ISVCE_CMD_VIDEO_CTL, ISVCE_CMD_CTL_SETDEFAULT};

  sDefaultIp.s_ive_ip.u4_timestamp_high = 0;
  sDefaultIp.s_ive_ip.u4_timestamp_low = 0;

  sDefaultIp.s_ive_ip.u4_size = sizeof(isvce_ctl_setdefault_ip_t);
  sDefaultOp.s_ive_op.u4_size = sizeof(isvce_ctl_setdefault_op_t);

  isvce_api_function(mCodecCtx, &sDefaultIp, &sDefaultOp, &s_api_cmds);
}

void Codec::getBufInfo() {
  isvce_ctl_getbufinfo_ip_t s_get_buf_info_ip{};
  isvce_ctl_getbufinfo_op_t s_get_buf_info_op{};

  isvce_api_cmds_t s_api_cmds{ISVCE_CMD_VIDEO_CTL, ISVCE_CMD_CTL_GETBUFINFO};

  s_get_buf_info_ip.s_ive_ip.u4_size = sizeof(isvce_ctl_getbufinfo_ip_t);
  s_get_buf_info_op.s_ive_op.u4_size = sizeof(isvce_ctl_getbufinfo_op_t);

  s_get_buf_info_ip.s_ive_ip.u4_max_ht = mInputDims.mHeight;
  s_get_buf_info_ip.s_ive_ip.u4_max_wd = mInputDims.mWidth;
  s_get_buf_info_ip.s_ive_ip.e_inp_color_fmt = mIvVideoColorFormat;

  isvce_api_function(mCodecCtx, &s_get_buf_info_ip, &s_get_buf_info_op, &s_api_cmds);
}

void Codec::setFrameRate() {
  isvce_ctl_set_frame_rate_ip_t sFrameRateIp{};
  isvce_ctl_set_frame_rate_op_t sFrameRateOp{};

  isvce_api_cmds_t s_api_cmds{ISVCE_CMD_VIDEO_CTL, ISVCE_CMD_CTL_SET_FRAMERATE};

  sFrameRateIp.s_ive_ip.u4_src_frame_rate = (UWORD32)mFrameRate;
  sFrameRateIp.s_ive_ip.u4_tgt_frame_rate = (UWORD32)mFrameRate;

  sFrameRateIp.s_ive_ip.u4_timestamp_high = 0;
  sFrameRateIp.s_ive_ip.u4_timestamp_low = 0;

  sFrameRateIp.s_ive_ip.u4_size = sizeof(isvce_ctl_set_frame_rate_ip_t);
  sFrameRateOp.s_ive_op.u4_size = sizeof(isvce_ctl_set_frame_rate_op_t);

  isvce_api_function(mCodecCtx, &sFrameRateIp, &sFrameRateOp, &s_api_cmds);
}

void Codec::setIpeParams() {
  isvce_ctl_set_ipe_params_ip_t sIpeParamsIp{};
  isvce_ctl_set_ipe_params_op_t sIpeParamsOp{};

  isvce_api_cmds_t s_api_cmds{ISVCE_CMD_VIDEO_CTL, ISVCE_CMD_CTL_SET_IPE_PARAMS};

  sIpeParamsIp.s_ive_ip.u4_enable_intra_4x4 = mIntra4x4;
  sIpeParamsIp.s_ive_ip.u4_enc_speed_preset = mEncSpeed;

  sIpeParamsIp.s_ive_ip.u4_timestamp_high = 0;
  sIpeParamsIp.s_ive_ip.u4_timestamp_low = 0;

  sIpeParamsIp.s_ive_ip.u4_size = sizeof(isvce_ctl_set_ipe_params_ip_t);
  sIpeParamsOp.s_ive_op.u4_size = sizeof(isvce_ctl_set_ipe_params_op_t);

  isvce_api_function(mCodecCtx, &sIpeParamsIp, &sIpeParamsOp, &s_api_cmds);
}

void Codec::setBitRate() {
  isvce_ctl_set_bitrate_ip_t sBitrateIp{};
  isvce_ctl_set_bitrate_op_t sBitrateOp{};

  isvce_api_cmds_t s_api_cmds{ISVCE_CMD_VIDEO_CTL, ISVCE_CMD_CTL_SET_BITRATE};
  std::vector<UWORD32> sTargetBitrates(mNumSpatialLayers, mBitrate);

  sBitrateIp.pu4_target_bitrate = sTargetBitrates.data();

  sBitrateIp.s_ive_ip.u4_timestamp_high = 0;
  sBitrateIp.s_ive_ip.u4_timestamp_low = 0;

  sBitrateIp.s_ive_ip.u4_size = sizeof(isvce_ctl_set_bitrate_ip_t);
  sBitrateOp.s_ive_op.u4_size = sizeof(isvce_ctl_set_bitrate_op_t);

  isvce_api_function(mCodecCtx, &sBitrateIp, &sBitrateOp, &s_api_cmds);
}

void Codec::setFrameType(IV_PICTURE_CODING_TYPE_T eFrameType) {
  isvce_ctl_set_frame_type_ip_t sFrameTypeIp{};
  isvce_ctl_set_frame_type_op_t sFrameTypeOp{};

  isvce_api_cmds_t s_api_cmds{ISVCE_CMD_VIDEO_CTL, ISVCE_CMD_CTL_SET_FRAMETYPE};

  sFrameTypeIp.s_ive_ip.e_frame_type = eFrameType;

  sFrameTypeIp.s_ive_ip.u4_timestamp_high = 0;
  sFrameTypeIp.s_ive_ip.u4_timestamp_low = 0;

  sFrameTypeIp.s_ive_ip.u4_size = sizeof(isvce_ctl_set_frame_type_ip_t);
  sFrameTypeOp.s_ive_op.u4_size = sizeof(isvce_ctl_set_frame_type_op_t);

  isvce_api_function(mCodecCtx, &sFrameTypeIp, &sFrameTypeOp, &s_api_cmds);
}

void Codec::setQp() {
  constexpr UWORD8 u1NumSliceTypes = 3;
  isvce_ctl_set_qp_ip_t s_QpIp{};
  isvce_ctl_set_qp_op_t s_QpOp{};

  isvce_api_cmds_t s_api_cmds{ISVCE_CMD_VIDEO_CTL, ISVCE_CMD_CTL_SET_QP};
  std::vector<UWORD32> sQps(u1NumSliceTypes * mNumSpatialLayers);
  std::vector<UWORD32> sMinQps(u1NumSliceTypes * mNumSpatialLayers);
  std::vector<UWORD32> sMaxQps(u1NumSliceTypes * mNumSpatialLayers);

  s_QpIp.pu4_i_qp = sQps.data();
  s_QpIp.pu4_i_qp_min = sMinQps.data();
  s_QpIp.pu4_i_qp_max = sMaxQps.data();

  s_QpIp.pu4_p_qp = sQps.data() + mNumSpatialLayers;
  s_QpIp.pu4_p_qp_min = sMinQps.data() + mNumSpatialLayers;
  s_QpIp.pu4_p_qp_max = sMaxQps.data() + mNumSpatialLayers;

  s_QpIp.pu4_b_qp = sQps.data() + mNumSpatialLayers * 2;
  s_QpIp.pu4_b_qp_min = sMinQps.data() + mNumSpatialLayers * 2;
  s_QpIp.pu4_b_qp_max = sMaxQps.data() + mNumSpatialLayers * 2;

  for (auto i = 0; i < mNumSpatialLayers; i++) {
    s_QpIp.pu4_i_qp[i] = m_I_QP;
    s_QpIp.pu4_i_qp_max[i] = kMaxQP;
    s_QpIp.pu4_i_qp_min[i] = kMinQP;

    s_QpIp.pu4_p_qp[i] = m_P_QP;
    s_QpIp.pu4_p_qp_max[i] = kMaxQP;
    s_QpIp.pu4_p_qp_min[i] = kMinQP;

    s_QpIp.pu4_b_qp[i] = m_B_QP;
    s_QpIp.pu4_b_qp_max[i] = kMaxQP;
    s_QpIp.pu4_b_qp_min[i] = kMinQP;
  }

  s_QpIp.s_ive_ip.u4_size = sizeof(isvce_ctl_set_qp_ip_t);
  s_QpOp.s_ive_op.u4_size = sizeof(isvce_ctl_set_qp_op_t);

  isvce_api_function(mCodecCtx, &s_QpIp, &s_QpOp, &s_api_cmds);
}

void Codec::setEncMode(IVE_ENC_MODE_T eEncMode) {
  isvce_ctl_set_enc_mode_ip_t sEncModeIp{};
  isvce_ctl_set_enc_mode_op_t sEncModeOp{};

  isvce_api_cmds_t s_api_cmds{ISVCE_CMD_VIDEO_CTL, ISVCE_CMD_CTL_SET_ENC_MODE};

  sEncModeIp.s_ive_ip.e_enc_mode = eEncMode;

  sEncModeIp.s_ive_ip.u4_timestamp_high = 0;
  sEncModeIp.s_ive_ip.u4_timestamp_low = 0;

  sEncModeIp.s_ive_ip.u4_size = sizeof(isvce_ctl_set_enc_mode_ip_t);
  sEncModeOp.s_ive_op.u4_size = sizeof(isvce_ctl_set_enc_mode_op_t);

  isvce_api_function(mCodecCtx, &sEncModeIp, &sEncModeOp, &s_api_cmds);
}

void Codec::setVbvParams() {
  isvce_ctl_set_vbv_params_ip_t sVbvIp{};
  isvce_ctl_set_vbv_params_op_t sVbvOp{};

  isvce_api_cmds_t s_api_cmds{ISVCE_CMD_VIDEO_CTL, ISVCE_CMD_CTL_SET_VBV_PARAMS};
  std::vector<UWORD32> sBufferDelays(mNumSpatialLayers, 1000);

  sVbvIp.pu4_vbv_buffer_delay = sBufferDelays.data();

  sVbvIp.s_ive_ip.u4_timestamp_high = 0;
  sVbvIp.s_ive_ip.u4_timestamp_low = 0;

  sVbvIp.s_ive_ip.u4_size = sizeof(isvce_ctl_set_vbv_params_ip_t);
  sVbvOp.s_ive_op.u4_size = sizeof(isvce_ctl_set_vbv_params_op_t);

  isvce_api_function(mCodecCtx, &sVbvIp, &sVbvOp, &s_api_cmds);
}

void Codec::setAirParams() {
  isvce_ctl_set_air_params_ip_t sAirIp{};
  isvce_ctl_set_air_params_op_t sAirOp{};

  isvce_api_cmds_t s_api_cmds{ISVCE_CMD_VIDEO_CTL, ISVCE_CMD_CTL_SET_AIR_PARAMS};

  sAirIp.s_ive_ip.e_air_mode = mAirMode;
  sAirIp.s_ive_ip.u4_air_refresh_period = mIntraRefresh;

  sAirIp.s_ive_ip.u4_timestamp_high = 0;
  sAirIp.s_ive_ip.u4_timestamp_low = 0;

  sAirIp.s_ive_ip.u4_size = sizeof(isvce_ctl_set_air_params_ip_t);
  sAirOp.s_ive_op.u4_size = sizeof(isvce_ctl_set_air_params_op_t);

  isvce_api_function(mCodecCtx, &sAirIp, &sAirOp, &s_api_cmds);
}

void Codec::setMeParams() {
  isvce_ctl_set_me_params_ip_t sMeParamsIp{};
  isvce_ctl_set_me_params_op_t sMeParamsOp{};

  isvce_api_cmds_t s_api_cmds{ISVCE_CMD_VIDEO_CTL, ISVCE_CMD_CTL_SET_ME_PARAMS};

  sMeParamsIp.s_ive_ip.u4_enable_fast_sad = mEnableFastSad;
  sMeParamsIp.s_ive_ip.u4_enable_alt_ref = mEnableAltRef;

  sMeParamsIp.s_ive_ip.u4_enable_hpel = mHalfPelEnable;
  sMeParamsIp.s_ive_ip.u4_enable_qpel = mQPelEnable;
  sMeParamsIp.s_ive_ip.u4_me_speed_preset = mMeSpeedPreset;
  sMeParamsIp.s_ive_ip.u4_srch_rng_x = mSearchRangeX;
  sMeParamsIp.s_ive_ip.u4_srch_rng_y = mSearchRangeY;

  sMeParamsIp.s_ive_ip.u4_timestamp_high = 0;
  sMeParamsIp.s_ive_ip.u4_timestamp_low = 0;

  sMeParamsIp.s_ive_ip.u4_size = sizeof(isvce_ctl_set_me_params_ip_t);
  sMeParamsOp.s_ive_op.u4_size = sizeof(isvce_ctl_set_me_params_op_t);

  isvce_api_function(mCodecCtx, &sMeParamsIp, &sMeParamsOp, &s_api_cmds);
}

void Codec::setGopParams() {
  isvce_ctl_set_gop_params_ip_t sGopParamsIp{};
  isvce_ctl_set_gop_params_op_t sGopParamsOp{};

  isvce_api_cmds_t s_api_cmds{ISVCE_CMD_VIDEO_CTL, ISVCE_CMD_CTL_SET_GOP_PARAMS};

  sGopParamsIp.s_ive_ip.u4_i_frm_interval = mIInterval;
  sGopParamsIp.s_ive_ip.u4_idr_frm_interval = mIDRInterval;

  sGopParamsIp.s_ive_ip.u4_timestamp_high = 0;
  sGopParamsIp.s_ive_ip.u4_timestamp_low = 0;

  sGopParamsIp.s_ive_ip.u4_size = sizeof(isvce_ctl_set_gop_params_ip_t);
  sGopParamsOp.s_ive_op.u4_size = sizeof(isvce_ctl_set_gop_params_op_t);

  isvce_api_function(mCodecCtx, &sGopParamsIp, &sGopParamsOp, &s_api_cmds);
}

void Codec::setProfileParams() {
  isvce_ctl_set_profile_params_ip_t sProfileParamsIp{};
  isvce_ctl_set_profile_params_op_t sProfileParamsOp{};

  isvce_api_cmds_t s_api_cmds{ISVCE_CMD_VIDEO_CTL, ISVCE_CMD_CTL_SET_PROFILE_PARAMS};

  sProfileParamsIp.s_ive_ip.e_profile = mProfile;
  if (sProfileParamsIp.s_ive_ip.e_profile == IV_PROFILE_BASE) {
    sProfileParamsIp.s_ive_ip.u4_entropy_coding_mode = 0;
  } else {
    sProfileParamsIp.s_ive_ip.u4_entropy_coding_mode = 1;
  }

  sProfileParamsIp.s_ive_ip.u4_timestamp_high = 0;
  sProfileParamsIp.s_ive_ip.u4_timestamp_low = 0;

  sProfileParamsIp.s_ive_ip.u4_size = sizeof(isvce_ctl_set_profile_params_ip_t);
  sProfileParamsOp.s_ive_op.u4_size = sizeof(isvce_ctl_set_profile_params_op_t);

  isvce_api_function(mCodecCtx, &sProfileParamsIp, &sProfileParamsOp, &s_api_cmds);
}

void Codec::setDeblockParams() {
  isvce_ctl_set_deblock_params_ip_t sDeblockParamsIp{};
  isvce_ctl_set_deblock_params_op_t sDeblockParamsOp{};

  isvce_api_cmds_t s_api_cmds{ISVCE_CMD_VIDEO_CTL, ISVCE_CMD_CTL_SET_DEBLOCK_PARAMS};

  sDeblockParamsIp.s_ive_ip.u4_disable_deblock_level = mDisableDeblockLevel;

  sDeblockParamsIp.s_ive_ip.u4_timestamp_high = 0;
  sDeblockParamsIp.s_ive_ip.u4_timestamp_low = 0;

  sDeblockParamsIp.s_ive_ip.u4_size = sizeof(isvce_ctl_set_deblock_params_ip_t);
  sDeblockParamsOp.s_ive_op.u4_size = sizeof(isvce_ctl_set_deblock_params_op_t);

  isvce_api_function(mCodecCtx, &sDeblockParamsIp, &sDeblockParamsOp, &s_api_cmds);
}

void Codec::setVuiParams() {
  isvce_vui_ip_t sVuiParamsIp{};
  isvce_vui_op_t sVuiParamsOp{};

  isvce_api_cmds_t s_api_cmds{ISVCE_CMD_VIDEO_CTL, ISVCE_CMD_CTL_SET_VUI_PARAMS};

  sVuiParamsIp.u1_aspect_ratio_info_present_flag = mAspectRatioFlag;
  sVuiParamsIp.u1_aspect_ratio_idc = 0;
  sVuiParamsIp.u2_sar_width = 0;
  sVuiParamsIp.u2_sar_height = 0;
  sVuiParamsIp.u1_overscan_info_present_flag = 0;
  sVuiParamsIp.u1_overscan_appropriate_flag = 0;
  sVuiParamsIp.u1_video_signal_type_present_flag = 1;
  sVuiParamsIp.u1_video_format = 0;
  sVuiParamsIp.u1_video_full_range_flag = 0;
  sVuiParamsIp.u1_colour_description_present_flag = 0;
  sVuiParamsIp.u1_colour_primaries = 0;
  sVuiParamsIp.u1_transfer_characteristics = 0;
  sVuiParamsIp.u1_matrix_coefficients = 0;
  sVuiParamsIp.u1_chroma_loc_info_present_flag = 0;
  sVuiParamsIp.u1_chroma_sample_loc_type_top_field = 0;
  sVuiParamsIp.u1_chroma_sample_loc_type_bottom_field = 0;
  sVuiParamsIp.u1_vui_timing_info_present_flag = 0;
  sVuiParamsIp.u4_vui_num_units_in_tick = 0;
  sVuiParamsIp.u4_vui_time_scale = 0;
  sVuiParamsIp.u1_fixed_frame_rate_flag = 0;
  sVuiParamsIp.u1_nal_hrd_parameters_present_flag = mNalHrdFlag;
  sVuiParamsIp.u1_vcl_hrd_parameters_present_flag = mVclHrdFlag;
  sVuiParamsIp.u1_low_delay_hrd_flag = 0;
  sVuiParamsIp.u1_pic_struct_present_flag = 0;
  sVuiParamsIp.u1_bitstream_restriction_flag = 0;
  sVuiParamsIp.u1_motion_vectors_over_pic_boundaries_flag = 0;
  sVuiParamsIp.u1_max_bytes_per_pic_denom = 0;
  sVuiParamsIp.u1_max_bits_per_mb_denom = 0;
  sVuiParamsIp.u1_log2_max_mv_length_horizontal = 0;
  sVuiParamsIp.u1_log2_max_mv_length_vertical = 0;
  sVuiParamsIp.u1_num_reorder_frames = 0;
  sVuiParamsIp.u1_max_dec_frame_buffering = 0;

  sVuiParamsIp.u4_size = sizeof(isvce_vui_ip_t);
  sVuiParamsOp.u4_size = sizeof(isvce_vui_op_t);

  isvce_api_function(mCodecCtx, &sVuiParamsIp, &sVuiParamsOp, &s_api_cmds);
}

void Codec::setSeiMdcvParams() {
  isvce_ctl_set_sei_mdcv_params_ip_t sSeiMdcvParamsIp{};
  isvce_ctl_set_sei_mdcv_params_op_t sSeiMdcvParamsOp{};

  isvce_api_cmds_t s_api_cmds{ISVCE_CMD_VIDEO_CTL, ISVCE_CMD_CTL_SET_SEI_MDCV_PARAMS};

  sSeiMdcvParamsIp.u1_sei_mdcv_params_present_flag = mSeiMdcvFlag;
  if (mSeiMdcvFlag) {
    for (int i4_count = 0; i4_count < kNumSeiMdcvPrimaries; ++i4_count) {
      sSeiMdcvParamsIp.au2_display_primaries_x[i4_count] = 30000;
      sSeiMdcvParamsIp.au2_display_primaries_y[i4_count] = 35000;
    }
    sSeiMdcvParamsIp.u2_white_point_x = 30000;
    sSeiMdcvParamsIp.u2_white_point_y = 35000;
    sSeiMdcvParamsIp.u4_max_display_mastering_luminance = 100000000;
    sSeiMdcvParamsIp.u4_min_display_mastering_luminance = 50000;
  }

  sSeiMdcvParamsIp.u4_timestamp_high = 0;
  sSeiMdcvParamsIp.u4_timestamp_low = 0;

  sSeiMdcvParamsIp.u4_size = sizeof(isvce_ctl_set_sei_mdcv_params_ip_t);
  sSeiMdcvParamsOp.u4_size = sizeof(isvce_ctl_set_sei_mdcv_params_op_t);

  isvce_api_function(mCodecCtx, &sSeiMdcvParamsIp, &sSeiMdcvParamsOp, &s_api_cmds);
}

void Codec::setSeiCllParams() {
  isvce_ctl_set_sei_cll_params_ip_t sSeiCllParamsIp{};
  isvce_ctl_set_sei_cll_params_op_t sSeiCllParamsOp{};

  isvce_api_cmds_t s_api_cmds{ISVCE_CMD_VIDEO_CTL, ISVCE_CMD_CTL_SET_SEI_CLL_PARAMS};

  sSeiCllParamsIp.u1_sei_cll_params_present_flag = mSeiCllFlag;

  if (mSeiCllFlag) {
    sSeiCllParamsIp.u2_max_content_light_level = 0;
    sSeiCllParamsIp.u2_max_pic_average_light_level = 0;
  }

  sSeiCllParamsIp.u4_timestamp_high = 0;
  sSeiCllParamsIp.u4_timestamp_low = 0;

  sSeiCllParamsIp.u4_size = sizeof(isvce_ctl_set_sei_cll_params_ip_t);
  sSeiCllParamsOp.u4_size = sizeof(isvce_ctl_set_sei_cll_params_op_t);

  isvce_api_function(mCodecCtx, &sSeiCllParamsIp, &sSeiCllParamsOp, &s_api_cmds);
}

void Codec::setSeiAveParams() {
  isvce_ctl_set_sei_ave_params_ip_t sSeiAveParamsIp{};
  isvce_ctl_set_sei_ave_params_op_t sSeiAveParamsOp{};

  isvce_api_cmds_t s_api_cmds{ISVCE_CMD_VIDEO_CTL, ISVCE_CMD_CTL_SET_SEI_AVE_PARAMS};

  sSeiAveParamsIp.u1_sei_ave_params_present_flag = mSeiAveFlag;

  if (mSeiAveFlag) {
    sSeiAveParamsIp.u4_ambient_illuminance = 1;
    sSeiAveParamsIp.u2_ambient_light_x = 0;
    sSeiAveParamsIp.u2_ambient_light_y = 0;
  }

  sSeiAveParamsIp.u4_timestamp_high = 0;
  sSeiAveParamsIp.u4_timestamp_low = 0;

  sSeiAveParamsIp.u4_size = sizeof(isvce_ctl_set_sei_ave_params_ip_t);
  sSeiAveParamsOp.u4_size = sizeof(isvce_ctl_set_sei_ave_params_op_t);

  isvce_api_function(mCodecCtx, &sSeiAveParamsIp, &sSeiAveParamsOp, &s_api_cmds);
}

void Codec::setSeiCcvParams() {
  isvce_ctl_set_sei_ccv_params_ip_t sSeiCcvParamsIp{};
  isvce_ctl_set_sei_ccv_params_op_t sSeiCcvParamsOp{};

  isvce_api_cmds_t s_api_cmds{ISVCE_CMD_VIDEO_CTL, ISVCE_CMD_CTL_SET_SEI_CCV_PARAMS};

  sSeiCcvParamsIp.u1_sei_ccv_params_present_flag = mSeiCcvFlag;

  if (mSeiCcvFlag) {
    sSeiCcvParamsIp.u1_ccv_cancel_flag = 0;
    sSeiCcvParamsIp.u1_ccv_persistence_flag = 1;
    sSeiCcvParamsIp.u1_ccv_primaries_present_flag = 1;
    sSeiCcvParamsIp.u1_ccv_min_luminance_value_present_flag = 1;
    sSeiCcvParamsIp.u1_ccv_max_luminance_value_present_flag = 1;
    sSeiCcvParamsIp.u1_ccv_avg_luminance_value_present_flag = 1;
    sSeiCcvParamsIp.u1_ccv_reserved_zero_2bits = 0;
    for (int i4_count = 0; i4_count < kNumSeiCcvPrimaries; ++i4_count) {
      sSeiCcvParamsIp.ai4_ccv_primaries_x[i4_count] = 1;
      sSeiCcvParamsIp.ai4_ccv_primaries_y[i4_count] = 1;
    }
    sSeiCcvParamsIp.u4_ccv_min_luminance_value = 1;
    sSeiCcvParamsIp.u4_ccv_max_luminance_value = 1;
    sSeiCcvParamsIp.u4_ccv_avg_luminance_value = 1;
  }

  sSeiCcvParamsIp.u4_timestamp_high = 0;
  sSeiCcvParamsIp.u4_timestamp_low = 0;

  sSeiCcvParamsIp.u4_size = sizeof(isvce_ctl_set_sei_ccv_params_ip_t);
  sSeiCcvParamsOp.u4_size = sizeof(isvce_ctl_set_sei_ccv_params_op_t);

  isvce_api_function(mCodecCtx, &sSeiCcvParamsIp, &sSeiCcvParamsOp, &s_api_cmds);
}

void Codec::logVersion() {
  isvce_ctl_getversioninfo_ip_t s_ctl_set_getversioninfo_ip{};
  isvce_ctl_getversioninfo_op_t s_ctl_set_getversioninfo_op{};

  CHAR ac_version_string[512];

  isvce_api_cmds_t s_api_cmds{ISVCE_CMD_VIDEO_CTL, ISVCE_CMD_CTL_GETVERSION};

  s_ctl_set_getversioninfo_ip.s_ive_ip.pu1_version = (UWORD8 *)ac_version_string;
  s_ctl_set_getversioninfo_ip.s_ive_ip.u4_version_bufsize = sizeof(ac_version_string);
  s_ctl_set_getversioninfo_ip.s_ive_ip.u4_size = sizeof(isvce_ctl_getversioninfo_ip_t);
  s_ctl_set_getversioninfo_op.s_ive_op.u4_size = sizeof(isvce_ctl_getversioninfo_op_t);

  isvce_api_function(mCodecCtx, (void *)&s_ctl_set_getversioninfo_ip, (void *)&s_ctl_set_getversioninfo_op, &s_api_cmds);
}

bool Codec::encodeFrames(const UWORD8 *data, size_t size) {
  isvce_video_encode_ip_t sEncodeIp{};
  isvce_video_encode_op_t sEncodeOp{};

  isvce_api_cmds_t s_api_cmds{ISVCE_CMD_VIDEO_ENCODE, ISVCE_CMD_CT_NA};
  iv_raw_buf_t *psInpRawBuf = &sEncodeIp.s_ive_ip.s_inp_buf;
  iv_raw_buf_t *psRecRawBuf = &sEncodeIp.s_ive_ip.s_recon_buf;

  size_t frameSize = mInputDims.getFrameSize();
  auto bytesLeft = std::min(size, frameSize);
  auto bytesConsumed = 0;
  UWORD32 numFrames = 0;

  sEncodeIp.s_ive_ip.s_out_buf.pv_buf = mEncBufs.mOutputBuf.data();
  sEncodeIp.s_ive_ip.s_out_buf.u4_bytes = 0;
  sEncodeIp.s_ive_ip.s_out_buf.u4_bufsize = static_cast<UWORD32>(mEncBufs.mOutputBuf.size());
  sEncodeOp.s_ive_op.s_out_buf.pv_buf = nullptr;
  sEncodeIp.s_ive_ip.pv_bufs = nullptr;
  sEncodeIp.s_ive_ip.pv_mb_info = nullptr;
  sEncodeIp.s_ive_ip.pv_pic_info = nullptr;
  sEncodeIp.s_ive_ip.u4_mb_info_type = 0;
  sEncodeIp.s_ive_ip.u4_pic_info_type = 0;
  sEncodeIp.s_ive_ip.u4_is_last = 0;

  sEncodeIp.s_ive_ip.u4_timestamp_high = 0;
  sEncodeIp.s_ive_ip.u4_timestamp_low = 0;

  memset(psInpRawBuf, 0, sizeof(iv_raw_buf_t));
  psInpRawBuf->u4_size = sizeof(iv_raw_buf_t);
  psInpRawBuf->e_color_fmt = mIvVideoColorFormat;

  sEncodeIp.s_ive_ip.u4_size = sizeof(isvce_video_encode_ip_t);
  sEncodeOp.s_ive_op.u4_size = sizeof(isvce_video_encode_op_t);

  isvce_api_function(mCodecCtx, &sEncodeIp, &sEncodeOp, &s_api_cmds);

  if (mEnableNaluInfoExport) {
    sEncodeIp.ps_nalu_info_buf = mEncBufs.mNaluInfoStructBuf.data();
    sEncodeOp.ps_nalu_info_buf = mEncBufs.mNaluInfoStructBuf.data() + mNumSpatialLayers;
  }

  while (!sEncodeOp.s_ive_op.u4_is_last && (kMaxEncodeCalls > (mNumSpatialLayers * numFrames))) {
    if (mEnableRecon) {
      setEncParams(psRecRawBuf, mEncBufs.mReconBuf, mInputDims);
    }

    if (mEnableNaluInfoExport) {
      for (auto i = 0; i < mNumSpatialLayers; i++) {
        sEncodeIp.ps_nalu_info_buf[i].pu1_buf = mEncBufs.mNaluInfoDataBuf[i].data();
        sEncodeIp.ps_nalu_info_buf[i].u4_num_bytes = 0;
        sEncodeIp.ps_nalu_info_buf[i].u4_buf_size = static_cast<UWORD32>(mEncBufs.mNaluInfoDataBuf[i].size());
      }
    }

    if (size > 0) {
      bytesLeft = std::min(size, frameSize);
      std::copy(data, data + bytesLeft, mEncBufs.mInputBuf.begin());
      std::fill(std::next(mEncBufs.mInputBuf.begin(), bytesLeft), mEncBufs.mInputBuf.end(), data[0]);
      setEncParams(psInpRawBuf, mEncBufs.mInputBuf, mInputDims, mIvVideoColorFormat);

      bytesConsumed = bytesLeft;
    } else {
      sEncodeIp.s_ive_ip.u4_is_last = 1;

      for (auto i = 0; i < 3; i++) {
        psInpRawBuf->apv_bufs[i] = nullptr;
      }

      bytesConsumed = 0;
    }

    if (mIsForceIdrEnabled && !sEncodeIp.s_ive_ip.u4_is_last) {
      if (numFrames == mForceIdrInterval) {
        setFrameType(IV_IDR_FRAME);
      }
    }

    if (mIsDynamicBitRateChangeEnabled && !sEncodeIp.s_ive_ip.u4_is_last) {
      if (numFrames == mDynamicBitRateInterval) {
        if (data[0] & 0x01) {
          mBitrate *= 2;
        } else {
          mBitrate /= 2;
        }

        setBitRate();
      }
    }

    if (mIsDynamicFrameRateChangeEnabled && !sEncodeIp.s_ive_ip.u4_is_last) {
      if (numFrames == mDynamicFrameRateInterval) {
        if (size > 1 && data[1] & 0x01) {
          mFrameRate *= 2;
        } else {
          mFrameRate /= 2;
        }

        setFrameRate();
      }
    }

    isvce_api_function(mCodecCtx, &sEncodeIp, &sEncodeOp, &s_api_cmds);

    if (!sEncodeOp.s_ive_op.u4_is_last) {
      numFrames++;
      data += bytesConsumed;
      size -= bytesConsumed;
    }
  }

  return true;
}

void Codec::setEncParams(iv_raw_buf_t *psInpRawBuf, std::vector<UWORD8> &buf, const FrameDims &dims, IV_COLOR_FORMAT_T colorFormat) {
  switch (colorFormat) {
  case IV_YUV_420SP_UV:
  case IV_YUV_420SP_VU: {
    WORD32 yStride = dims.mWidth;
    WORD32 uStride = dims.mWidth / 2;

    psInpRawBuf->apv_bufs[0] = buf.data();
    psInpRawBuf->apv_bufs[1] = buf.data() + dims.mWidth * dims.mHeight;

    psInpRawBuf->au4_wd[0] = dims.mWidth;
    psInpRawBuf->au4_wd[1] = dims.mWidth;

    psInpRawBuf->au4_ht[0] = dims.mHeight;
    psInpRawBuf->au4_ht[1] = dims.mHeight / 2;

    psInpRawBuf->au4_strd[0] = yStride;
    psInpRawBuf->au4_strd[1] = uStride;

    break;
  }
  default: {
    WORD32 yStride = dims.mWidth;
    WORD32 uStride = dims.mWidth / 2;
    WORD32 vStride = dims.mWidth / 2;

    psInpRawBuf->apv_bufs[0] = buf.data();
    psInpRawBuf->apv_bufs[1] = buf.data() + dims.mWidth * dims.mHeight;
    psInpRawBuf->apv_bufs[2] = buf.data() + (dims.mWidth * dims.mHeight * 5) / 4;

    psInpRawBuf->au4_wd[0] = dims.mWidth;
    psInpRawBuf->au4_wd[1] = dims.mWidth / 2;
    psInpRawBuf->au4_wd[2] = dims.mWidth / 2;

    psInpRawBuf->au4_ht[0] = dims.mHeight;
    psInpRawBuf->au4_ht[1] = dims.mHeight / 2;
    psInpRawBuf->au4_ht[2] = dims.mHeight / 2;

    psInpRawBuf->au4_strd[0] = yStride;
    psInpRawBuf->au4_strd[1] = uStride;
    psInpRawBuf->au4_strd[2] = vStride;

    break;
  }
  }
}

extern "C" int LLVMFuzzerTestOneInput(const UWORD8 *data, size_t size) {
  if (size < IDX_LAST) {
    return 0;
  }

  std::unique_ptr<Codec> codec = std::make_unique<Codec>();

  if (codec->initEncoder(data)) {
    codec->encodeFrames(data, size);
  }

  return 0;
}
