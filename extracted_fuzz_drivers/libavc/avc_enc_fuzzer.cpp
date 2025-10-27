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
#include <malloc.h>
#include <string.h>
#include <tuple>
#include <vector>

#include "ih264_defs.h"
#include "ih264_typedefs.h"
#include "ih264e.h"
#include "ih264e_error.h"
#define ive_api_function ih264e_api_function
typedef std::tuple<uint8_t *, uint8_t *, uint8_t *> bufferPtrs;

constexpr static int kMaxNumEncodeCalls = 100;
constexpr uint32_t kHeaderLength = 0x800;
constexpr int16_t kCompressionRatio = 1;

constexpr int kMeSpeedPreset[] = {0, 50, 75, 100};
constexpr IVE_AIR_MODE_T kAirMode[] = {IVE_AIR_MODE_NONE, IVE_AIR_MODE_CYCLIC, IVE_AIR_MODE_RANDOM};
constexpr IVE_SPEED_CONFIG kEncSpeed[] = {IVE_CONFIG, IVE_SLOWEST, IVE_NORMAL, IVE_FAST, IVE_HIGH_SPEED, IVE_FASTEST};
constexpr IV_PROFILE_T kProfle[] = {IV_PROFILE_BASE, IV_PROFILE_MAIN};
constexpr IVE_RC_MODE_T kRCMode[] = {IVE_RC_NONE, IVE_RC_STORAGE, IVE_RC_CBR_NON_LOW_DELAY, IVE_RC_CBR_LOW_DELAY};
constexpr IV_COLOR_FORMAT_T kSupportedColorFormats[] = {IV_YUV_420P, IV_YUV_420SP_UV, IV_YUV_422ILE, IV_YUV_420SP_VU};

constexpr size_t kAirModeNum = std::size(kAirMode);
constexpr size_t kEncSpeedNum = std::size(kEncSpeed);
constexpr size_t kMeSpeedPresetNum = std::size(kMeSpeedPreset);
constexpr size_t kProfleNum = std::size(kProfle);
constexpr size_t kRCModeNum = std::size(kRCMode);
constexpr size_t kSupportedColorFormatsNum = std::size(kSupportedColorFormats);
constexpr size_t kMinQP = 4;
constexpr size_t kMaxWidth = 10240;
constexpr size_t kMaxHeight = 10240;
constexpr size_t kMaxBitrate = 500000000;

enum { IDX_WD_BYTE_1, IDX_WD_BYTE_2, IDX_HT_BYTE_1, IDX_HT_BYTE_2, IDX_COLOR_FORMAT, IDX_ARCH_TYPE, IDX_RC_MODE, IDX_NUM_CORES, IDX_NUM_B_FRAMES, IDX_ENC_SPEED, IDX_CONSTRAINED_INTRA_FLAG, IDX_INTRA_4x4, IDX_I_FRAME_QP, IDX_P_FRAME_QP, IDX_B_FRAME_QP, IDX_BITRATE_BYTE_1, IDX_BITRATE_BYTE_2, IDX_FRAME_RATE, IDX_INTRA_REFRESH, IDX_ENABLE_HALF_PEL, IDX_ENABLE_Q_PEL, IDX_ME_SPEED_PRESET, IDX_AIR_MODE, IDX_DISABLE_DEBLOCK_LEVEL, IDX_SEARCH_RANGE_X, IDX_SEARCH_RANGE_Y, IDX_I_INTERVAL, IDX_IDR_INTERVAL, IDX_SEI_MDCV_FLAG, IDX_SEI_CLL_FLAG, IDX_SEI_AVE_FLAG, IDX_SEI_CCV_FLAG, IDX_SEI_SII_FLAG, IDX_PROFILE, IDX_ASPECT_RATIO_FLAG, IDX_NAL_HRD_FLAG, IDX_VCL_HRD_FLAG, IDX_ENABLE_FORCE_IDR, IDX_ENABLE_DYNAMIC_BITRATE, IDX_ENABLE_DYNAMIC_FRAME_RATE, IDX_FORCE_IDR_INTERVAL, IDX_DYNAMIC_BITRATE_INTERVAL, IDX_DYNAMIC_FRAME_RATE_INTERVAL, IDX_SEND_EOS_WITH_LAST_FRAME, IDX_LAST };

class Codec {
public:
  Codec() = default;
  ~Codec() { deInitEncoder(); }
  bool initEncoder(const uint8_t **pdata, size_t *psize);
  void encodeFrames(const uint8_t *data, size_t size);
  void deInitEncoder();

private:
  bufferPtrs setEncParams(iv_raw_buf_t *psInpRawBuf, const uint8_t *data, size_t frameSize);
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
  void setSeiSiiParams();
  void logVersion();
  bool mHalfPelEnable = 1;
  bool mQPelEnable = 1;
  bool mIntra4x4 = 0;
  bool mEnableFastSad = 0;
  bool mEnableAltRef = 0;
  bool mConstrainedIntraFlag = 0;
  bool mSeiCllFlag = 1;
  bool mSeiAveFlag = 1;
  bool mSeiCcvFlag = 1;
  bool mSeiMdcvFlag = 1;
  bool mSeiSiiFlag = 1;
  bool mAspectRatioFlag = 0;
  bool mNalHrdFlag = 0;
  bool mVclHrdFlag = 0;
  bool mIsForceIdrEnabled = false;
  bool mIsDynamicBitRateChangeEnabled = false;
  bool mIsDynamicFrameRateChangeEnabled = false;
  bool mSendEosWithLastFrame = false;
  uint32_t mWidth = 2560;
  uint32_t mHeight = 2560;
  uint32_t mAvcEncLevel = 41;
  uint32_t mNumMemRecords = 0;
  uint32_t mNumCores = 1;
  uint32_t mBframes = 0;
  uint32_t mSliceParam = 256;
  uint32_t mMeSpeedPreset = 100;
  uint32_t mIInterval = 60;
  uint32_t mIDRInterval = 60;
  uint32_t mDisableDeblockLevel = 0;
  uint32_t m_I_QP = 22;
  uint32_t m_P_QP = 28;
  uint32_t m_B_QP = 22;
  uint32_t mIntraRefresh = 30;
  uint32_t mSearchRangeX = 64;
  uint32_t mSearchRangeY = 48;
  uint32_t mForceIdrInterval = 0;         // in number of frames
  uint32_t mDynamicBitRateInterval = 0;   // in number of frames
  uint32_t mDynamicFrameRateInterval = 0; // in number of frames
  uint64_t mBitrate = 6000000;
  float mFrameRate = 30;
  iv_obj_t *mCodecCtx = nullptr;
  iv_mem_rec_t *mMemRecords = nullptr;
  IVE_AIR_MODE_T mAirMode = IVE_AIR_MODE_NONE;
  IVE_SPEED_CONFIG mEncSpeed = IVE_NORMAL;
  IVE_RC_MODE_T mRCMode = IVE_RC_STORAGE;
  IV_ARCH_T mArch = ARCH_NA;
  IVE_SLICE_MODE_T mSliceMode = IVE_SLICE_MODE_NONE;
  IV_COLOR_FORMAT_T mIvVideoColorFormat = IV_YUV_420P;
  IV_COLOR_FORMAT_T mReconFormat = IV_YUV_420P;
  IV_PROFILE_T mProfile = IV_PROFILE_BASE;
};

bool Codec::initEncoder(const uint8_t **pdata, size_t *psize) {
  uint8_t *data = const_cast<uint8_t *>(*pdata);
  mWidth = ((data[IDX_WD_BYTE_1] << 8) | data[IDX_WD_BYTE_2]) % kMaxWidth;
  mHeight = ((data[IDX_HT_BYTE_1] << 8) | data[IDX_HT_BYTE_2]) % kMaxHeight;

  mIvVideoColorFormat = kSupportedColorFormats[data[IDX_COLOR_FORMAT] % kSupportedColorFormatsNum];
  mArch = ((data[IDX_ARCH_TYPE] & 0x03) == 0x00) ? ARCH_ARM_NONEON : ARCH_NA;
  mRCMode = kRCMode[data[IDX_RC_MODE] % kRCModeNum];
  mNumCores = (data[IDX_NUM_CORES] & 0x07) + 1;
  mBframes = data[IDX_NUM_B_FRAMES] & 0x07;
  mEncSpeed = kEncSpeed[data[IDX_ENC_SPEED] % kEncSpeedNum];
  mConstrainedIntraFlag = data[IDX_CONSTRAINED_INTRA_FLAG] & 0x01;
  mIntra4x4 = data[IDX_INTRA_4x4] & 0x01;
  m_I_QP = (data[IDX_I_FRAME_QP] % (MAX_H264_QP - kMinQP)) + kMinQP;
  m_P_QP = (data[IDX_P_FRAME_QP] % (MAX_H264_QP - kMinQP)) + kMinQP;
  m_B_QP = (data[IDX_B_FRAME_QP] % (MAX_H264_QP - kMinQP)) + kMinQP;
  mBitrate = (((data[IDX_BITRATE_BYTE_1] << 8) | data[IDX_BITRATE_BYTE_2]) * 1000) % kMaxBitrate;
  mFrameRate = data[IDX_FRAME_RATE];
  mIntraRefresh = data[IDX_INTRA_REFRESH] + 1;
  mHalfPelEnable = data[IDX_ENABLE_HALF_PEL] & 0x01;
  mQPelEnable = data[IDX_ENABLE_Q_PEL] & 0x01;
  mMeSpeedPreset = kMeSpeedPreset[data[IDX_ME_SPEED_PRESET] % kMeSpeedPresetNum];
  mAirMode = kAirMode[data[IDX_AIR_MODE] % kAirModeNum];
  mDisableDeblockLevel = data[IDX_DISABLE_DEBLOCK_LEVEL] & 0x03;
  mSearchRangeX = data[IDX_SEARCH_RANGE_X];
  mSearchRangeY = data[IDX_SEARCH_RANGE_Y];
  mIInterval = data[IDX_I_INTERVAL] + 1;
  mIDRInterval = data[IDX_IDR_INTERVAL] + 1;
  mSeiMdcvFlag = data[IDX_SEI_MDCV_FLAG] & 0x01;
  mSeiCllFlag = data[IDX_SEI_CLL_FLAG] & 0x01;
  mSeiAveFlag = data[IDX_SEI_AVE_FLAG] & 0x01;
  mSeiCcvFlag = data[IDX_SEI_CCV_FLAG] & 0x01;
  mSeiSiiFlag = data[IDX_SEI_SII_FLAG] & 0x01;
  mProfile = kProfle[data[IDX_PROFILE] % kProfleNum];
  mAspectRatioFlag = data[IDX_ASPECT_RATIO_FLAG] & 0x01;
  mNalHrdFlag = data[IDX_NAL_HRD_FLAG] & 0x01;
  mVclHrdFlag = data[IDX_VCL_HRD_FLAG] & 0x01;
  mIsForceIdrEnabled = data[IDX_ENABLE_FORCE_IDR] & 0x01;
  mIsDynamicBitRateChangeEnabled = data[IDX_ENABLE_DYNAMIC_BITRATE] & 0x01;
  mIsDynamicFrameRateChangeEnabled = data[IDX_ENABLE_DYNAMIC_FRAME_RATE] & 0x01;
  mSendEosWithLastFrame = data[IDX_SEND_EOS_WITH_LAST_FRAME] & 0x01;
  mForceIdrInterval = data[IDX_FORCE_IDR_INTERVAL] & 0x07;
  mDynamicBitRateInterval = data[IDX_DYNAMIC_BITRATE_INTERVAL] & 0x07;
  mDynamicFrameRateInterval = data[IDX_DYNAMIC_FRAME_RATE_INTERVAL] & 0x07;

  /* Getting Number of MemRecords */
  iv_num_mem_rec_ip_t sNumMemRecIp{};
  iv_num_mem_rec_op_t sNumMemRecOp{};

  sNumMemRecIp.u4_size = sizeof(iv_num_mem_rec_ip_t);
  sNumMemRecOp.u4_size = sizeof(iv_num_mem_rec_op_t);
  sNumMemRecIp.e_cmd = IV_CMD_GET_NUM_MEM_REC;

  if (IV_SUCCESS != ive_api_function(nullptr, &sNumMemRecIp, &sNumMemRecOp)) {
    return false;
  }
  mNumMemRecords = sNumMemRecOp.u4_num_mem_rec;
  mMemRecords = (iv_mem_rec_t *)malloc(mNumMemRecords * sizeof(iv_mem_rec_t));
  if (!mMemRecords) {
    return false;
  }
  iv_mem_rec_t *psMemRec;
  psMemRec = mMemRecords;
  for (size_t i = 0; i < mNumMemRecords; ++i) {
    psMemRec->u4_size = sizeof(iv_mem_rec_t);
    psMemRec->pv_base = nullptr;
    psMemRec->u4_mem_size = 0;
    psMemRec->u4_mem_alignment = 0;
    psMemRec->e_mem_type = IV_NA_MEM_TYPE;
    ++psMemRec;
  }

  /* Getting MemRecords Attributes */
  iv_fill_mem_rec_ip_t sFillMemRecIp{};
  iv_fill_mem_rec_op_t sFillMemRecOp{};

  sFillMemRecIp.u4_size = sizeof(iv_fill_mem_rec_ip_t);
  sFillMemRecOp.u4_size = sizeof(iv_fill_mem_rec_op_t);

  sFillMemRecIp.e_cmd = IV_CMD_FILL_NUM_MEM_REC;
  sFillMemRecIp.ps_mem_rec = mMemRecords;
  sFillMemRecIp.u4_num_mem_rec = mNumMemRecords;
  sFillMemRecIp.u4_max_wd = mWidth;
  sFillMemRecIp.u4_max_ht = mHeight;
  sFillMemRecIp.u4_max_level = mAvcEncLevel;
  sFillMemRecIp.e_color_format = IV_YUV_420SP_VU;
  sFillMemRecIp.u4_max_ref_cnt = 2;
  sFillMemRecIp.u4_max_reorder_cnt = 0;
  sFillMemRecIp.u4_max_srch_rng_x = 256;
  sFillMemRecIp.u4_max_srch_rng_y = 256;

  if (IV_SUCCESS != ive_api_function(nullptr, &sFillMemRecIp, &sFillMemRecOp)) {
    return false;
  }
  /* Allocating Memory for Mem Records */
  psMemRec = mMemRecords;
  for (size_t i = 0; i < mNumMemRecords; ++i) {
    posix_memalign(&psMemRec->pv_base, psMemRec->u4_mem_alignment, psMemRec->u4_mem_size);
    if (!psMemRec->pv_base) {
      return false;
    }
    ++psMemRec;
  }

  /* Codec Instance Creation */
  ive_init_ip_t sInitIp{};
  ive_init_op_t sInitOp{};

  mCodecCtx = (iv_obj_t *)mMemRecords[0].pv_base;
  mCodecCtx->u4_size = sizeof(iv_obj_t);
  mCodecCtx->pv_fxns = (void *)ive_api_function;

  sInitIp.u4_size = sizeof(ive_init_ip_t);
  sInitOp.u4_size = sizeof(ive_init_op_t);

  sInitIp.e_cmd = IV_CMD_INIT;
  sInitIp.u4_num_mem_rec = mNumMemRecords;
  sInitIp.ps_mem_rec = mMemRecords;
  sInitIp.u4_max_wd = mWidth;
  sInitIp.u4_max_ht = mHeight;
  sInitIp.u4_max_ref_cnt = 2;
  sInitIp.u4_max_reorder_cnt = 0;
  sInitIp.u4_max_level = mAvcEncLevel;
  sInitIp.e_inp_color_fmt = mIvVideoColorFormat;
  sInitIp.u4_enable_recon = 0;
  sInitIp.e_recon_color_fmt = mReconFormat;
  sInitIp.e_rc_mode = mRCMode;
  sInitIp.u4_max_framerate = 120000;
  sInitIp.u4_max_bitrate = 240000000;
  sInitIp.u4_num_bframes = mBframes;
  sInitIp.e_content_type = IV_PROGRESSIVE;
  sInitIp.u4_max_srch_rng_x = 256;
  sInitIp.u4_max_srch_rng_y = 256;
  sInitIp.e_slice_mode = mSliceMode;
  sInitIp.u4_slice_param = mSliceParam;
  sInitIp.e_arch = mArch;
  sInitIp.e_soc = SOC_GENERIC;

  if (IV_SUCCESS != ive_api_function(mCodecCtx, &sInitIp, &sInitOp)) {
    return false;
  }

  logVersion();
  setDefault();
  getBufInfo();
  setNumCores();
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
  setVuiParams();
  setSeiMdcvParams();
  setSeiCllParams();
  setSeiAveParams();
  setSeiCcvParams();
  setSeiSiiParams();
  setProfileParams();
  setEncMode(IVE_ENC_MODE_HEADER);

  *pdata += IDX_LAST;
  *psize -= IDX_LAST;
  return true;
}

void Codec::setDimensions() {
  ive_ctl_set_dimensions_ip_t sDimensionsIp{};
  ive_ctl_set_dimensions_op_t sDimensionsOp{};

  sDimensionsIp.e_cmd = IVE_CMD_VIDEO_CTL;
  sDimensionsIp.e_sub_cmd = IVE_CMD_CTL_SET_DIMENSIONS;
  sDimensionsIp.u4_ht = mHeight;
  sDimensionsIp.u4_wd = mWidth;

  sDimensionsIp.u4_timestamp_high = -1;
  sDimensionsIp.u4_timestamp_low = -1;

  sDimensionsIp.u4_size = sizeof(ive_ctl_set_dimensions_ip_t);
  sDimensionsOp.u4_size = sizeof(ive_ctl_set_dimensions_op_t);

  ive_api_function(mCodecCtx, &sDimensionsIp, &sDimensionsOp);
  return;
}

void Codec::setNumCores() {
  ive_ctl_set_num_cores_ip_t sNumCoresIp{};
  ive_ctl_set_num_cores_op_t sNumCoresOp{};

  sNumCoresIp.e_cmd = IVE_CMD_VIDEO_CTL;
  sNumCoresIp.e_sub_cmd = IVE_CMD_CTL_SET_NUM_CORES;
  sNumCoresIp.u4_num_cores = mNumCores;

  sNumCoresIp.u4_timestamp_high = -1;
  sNumCoresIp.u4_timestamp_low = -1;

  sNumCoresIp.u4_size = sizeof(ive_ctl_set_num_cores_ip_t);
  sNumCoresOp.u4_size = sizeof(ive_ctl_set_num_cores_op_t);

  ive_api_function(mCodecCtx, (void *)&sNumCoresIp, (void *)&sNumCoresOp);
  return;
}

void Codec::setDefault() {
  ive_ctl_setdefault_ip_t sDefaultIp{};
  ive_ctl_setdefault_op_t sDefaultOp{};

  sDefaultIp.e_cmd = IVE_CMD_VIDEO_CTL;
  sDefaultIp.e_sub_cmd = IVE_CMD_CTL_SETDEFAULT;

  sDefaultIp.u4_timestamp_high = -1;
  sDefaultIp.u4_timestamp_low = -1;

  sDefaultIp.u4_size = sizeof(ive_ctl_setdefault_ip_t);
  sDefaultOp.u4_size = sizeof(ive_ctl_setdefault_op_t);

  ive_api_function(mCodecCtx, &sDefaultIp, &sDefaultOp);
  return;
}

void Codec::getBufInfo() {
  ih264e_ctl_getbufinfo_ip_t sGetBufInfoIp{};
  ih264e_ctl_getbufinfo_op_t sGetBufInfoOp{};

  sGetBufInfoIp.s_ive_ip.u4_size = sizeof(ih264e_ctl_getbufinfo_ip_t);
  sGetBufInfoOp.s_ive_op.u4_size = sizeof(ih264e_ctl_getbufinfo_op_t);

  sGetBufInfoIp.s_ive_ip.e_cmd = IVE_CMD_VIDEO_CTL;
  sGetBufInfoIp.s_ive_ip.e_sub_cmd = IVE_CMD_CTL_GETBUFINFO;
  sGetBufInfoIp.s_ive_ip.u4_max_ht = mHeight;
  sGetBufInfoIp.s_ive_ip.u4_max_wd = mWidth;
  sGetBufInfoIp.s_ive_ip.e_inp_color_fmt = mIvVideoColorFormat;

  ih264e_api_function(mCodecCtx, &sGetBufInfoIp, &sGetBufInfoOp);
  return;
}

void Codec::setFrameRate() {
  ive_ctl_set_frame_rate_ip_t sFrameRateIp{};
  ive_ctl_set_frame_rate_op_t sFrameRateOp{};

  sFrameRateIp.e_cmd = IVE_CMD_VIDEO_CTL;
  sFrameRateIp.e_sub_cmd = IVE_CMD_CTL_SET_FRAMERATE;
  sFrameRateIp.u4_src_frame_rate = mFrameRate;
  sFrameRateIp.u4_tgt_frame_rate = mFrameRate;

  sFrameRateIp.u4_timestamp_high = -1;
  sFrameRateIp.u4_timestamp_low = -1;

  sFrameRateIp.u4_size = sizeof(ive_ctl_set_frame_rate_ip_t);
  sFrameRateOp.u4_size = sizeof(ive_ctl_set_frame_rate_op_t);

  ive_api_function(mCodecCtx, &sFrameRateIp, &sFrameRateOp);
  return;
}

void Codec::setIpeParams() {
  ive_ctl_set_ipe_params_ip_t sIpeParamsIp{};
  ive_ctl_set_ipe_params_op_t sIpeParamsOp{};

  sIpeParamsIp.e_cmd = IVE_CMD_VIDEO_CTL;
  sIpeParamsIp.e_sub_cmd = IVE_CMD_CTL_SET_IPE_PARAMS;
  sIpeParamsIp.u4_enable_intra_4x4 = mIntra4x4;
  sIpeParamsIp.u4_enc_speed_preset = mEncSpeed;
  sIpeParamsIp.u4_constrained_intra_pred = mConstrainedIntraFlag;

  sIpeParamsIp.u4_timestamp_high = -1;
  sIpeParamsIp.u4_timestamp_low = -1;

  sIpeParamsIp.u4_size = sizeof(ive_ctl_set_ipe_params_ip_t);
  sIpeParamsOp.u4_size = sizeof(ive_ctl_set_ipe_params_op_t);

  ive_api_function(mCodecCtx, &sIpeParamsIp, &sIpeParamsOp);
  return;
}

void Codec::setBitRate() {
  ive_ctl_set_bitrate_ip_t sBitrateIp{};
  ive_ctl_set_bitrate_op_t sBitrateOp{};

  sBitrateIp.e_cmd = IVE_CMD_VIDEO_CTL;
  sBitrateIp.e_sub_cmd = IVE_CMD_CTL_SET_BITRATE;
  sBitrateIp.u4_target_bitrate = mBitrate;

  sBitrateIp.u4_timestamp_high = -1;
  sBitrateIp.u4_timestamp_low = -1;

  sBitrateIp.u4_size = sizeof(ive_ctl_set_bitrate_ip_t);
  sBitrateOp.u4_size = sizeof(ive_ctl_set_bitrate_op_t);

  ive_api_function(mCodecCtx, &sBitrateIp, &sBitrateOp);
  return;
}

void Codec::setFrameType(IV_PICTURE_CODING_TYPE_T eFrameType) {
  ive_ctl_set_frame_type_ip_t sFrameTypeIp{};
  ive_ctl_set_frame_type_op_t sFrameTypeOp{};

  sFrameTypeIp.e_cmd = IVE_CMD_VIDEO_CTL;
  sFrameTypeIp.e_sub_cmd = IVE_CMD_CTL_SET_FRAMETYPE;
  sFrameTypeIp.e_frame_type = eFrameType;

  sFrameTypeIp.u4_timestamp_high = -1;
  sFrameTypeIp.u4_timestamp_low = -1;

  sFrameTypeIp.u4_size = sizeof(ive_ctl_set_frame_type_ip_t);
  sFrameTypeOp.u4_size = sizeof(ive_ctl_set_frame_type_op_t);

  ive_api_function(mCodecCtx, &sFrameTypeIp, &sFrameTypeOp);
  return;
}

void Codec::setQp() {
  ive_ctl_set_qp_ip_t s_QpIp{};
  ive_ctl_set_qp_op_t s_QpOp{};

  s_QpIp.e_cmd = IVE_CMD_VIDEO_CTL;
  s_QpIp.e_sub_cmd = IVE_CMD_CTL_SET_QP;

  s_QpIp.u4_i_qp = m_I_QP;
  s_QpIp.u4_i_qp_max = MAX_H264_QP;
  s_QpIp.u4_i_qp_min = kMinQP;

  s_QpIp.u4_p_qp = m_P_QP;
  s_QpIp.u4_p_qp_max = MAX_H264_QP;
  s_QpIp.u4_p_qp_min = kMinQP;

  s_QpIp.u4_b_qp = m_B_QP;
  s_QpIp.u4_b_qp_max = MAX_H264_QP;
  s_QpIp.u4_b_qp_min = kMinQP;

  s_QpIp.u4_timestamp_high = -1;
  s_QpIp.u4_timestamp_low = -1;

  s_QpIp.u4_size = sizeof(ive_ctl_set_qp_ip_t);
  s_QpOp.u4_size = sizeof(ive_ctl_set_qp_op_t);

  ive_api_function(mCodecCtx, &s_QpIp, &s_QpOp);
  return;
}

void Codec::setEncMode(IVE_ENC_MODE_T eEncMode) {
  ive_ctl_set_enc_mode_ip_t sEncModeIp{};
  ive_ctl_set_enc_mode_op_t sEncModeOp{};

  sEncModeIp.e_cmd = IVE_CMD_VIDEO_CTL;
  sEncModeIp.e_sub_cmd = IVE_CMD_CTL_SET_ENC_MODE;
  sEncModeIp.e_enc_mode = eEncMode;

  sEncModeIp.u4_timestamp_high = -1;
  sEncModeIp.u4_timestamp_low = -1;

  sEncModeIp.u4_size = sizeof(ive_ctl_set_enc_mode_ip_t);
  sEncModeOp.u4_size = sizeof(ive_ctl_set_enc_mode_op_t);

  ive_api_function(mCodecCtx, &sEncModeIp, &sEncModeOp);
  return;
}

void Codec::setVbvParams() {
  ive_ctl_set_vbv_params_ip_t sVbvIp{};
  ive_ctl_set_vbv_params_op_t sVbvOp{};

  sVbvIp.e_cmd = IVE_CMD_VIDEO_CTL;
  sVbvIp.e_sub_cmd = IVE_CMD_CTL_SET_VBV_PARAMS;
  sVbvIp.u4_vbv_buf_size = 0;
  sVbvIp.u4_vbv_buffer_delay = 1000;

  sVbvIp.u4_timestamp_high = -1;
  sVbvIp.u4_timestamp_low = -1;

  sVbvIp.u4_size = sizeof(ive_ctl_set_vbv_params_ip_t);
  sVbvOp.u4_size = sizeof(ive_ctl_set_vbv_params_op_t);

  ive_api_function(mCodecCtx, &sVbvIp, &sVbvOp);
  return;
}

void Codec::setAirParams() {
  ive_ctl_set_air_params_ip_t sAirIp{};
  ive_ctl_set_air_params_op_t sAirOp{};

  sAirIp.e_cmd = IVE_CMD_VIDEO_CTL;
  sAirIp.e_sub_cmd = IVE_CMD_CTL_SET_AIR_PARAMS;
  sAirIp.e_air_mode = mAirMode;
  sAirIp.u4_air_refresh_period = mIntraRefresh;

  sAirIp.u4_timestamp_high = -1;
  sAirIp.u4_timestamp_low = -1;

  sAirIp.u4_size = sizeof(ive_ctl_set_air_params_ip_t);
  sAirOp.u4_size = sizeof(ive_ctl_set_air_params_op_t);

  ive_api_function(mCodecCtx, &sAirIp, &sAirOp);
  return;
}

void Codec::setMeParams() {
  ive_ctl_set_me_params_ip_t sMeParamsIp{};
  ive_ctl_set_me_params_op_t sMeParamsOp{};

  sMeParamsIp.e_cmd = IVE_CMD_VIDEO_CTL;
  sMeParamsIp.e_sub_cmd = IVE_CMD_CTL_SET_ME_PARAMS;
  sMeParamsIp.u4_enable_fast_sad = mEnableFastSad;
  sMeParamsIp.u4_enable_alt_ref = mEnableAltRef;

  sMeParamsIp.u4_enable_hpel = mHalfPelEnable;
  sMeParamsIp.u4_enable_qpel = mQPelEnable;
  sMeParamsIp.u4_me_speed_preset = mMeSpeedPreset;
  sMeParamsIp.u4_srch_rng_x = mSearchRangeX;
  sMeParamsIp.u4_srch_rng_y = mSearchRangeY;

  sMeParamsIp.u4_timestamp_high = -1;
  sMeParamsIp.u4_timestamp_low = -1;

  sMeParamsIp.u4_size = sizeof(ive_ctl_set_me_params_ip_t);
  sMeParamsOp.u4_size = sizeof(ive_ctl_set_me_params_op_t);

  ive_api_function(mCodecCtx, &sMeParamsIp, &sMeParamsOp);
  return;
}

void Codec::setGopParams() {
  ive_ctl_set_gop_params_ip_t sGopParamsIp{};
  ive_ctl_set_gop_params_op_t sGopParamsOp{};

  sGopParamsIp.e_cmd = IVE_CMD_VIDEO_CTL;
  sGopParamsIp.e_sub_cmd = IVE_CMD_CTL_SET_GOP_PARAMS;

  sGopParamsIp.u4_i_frm_interval = mIInterval;
  sGopParamsIp.u4_idr_frm_interval = mIDRInterval;

  sGopParamsIp.u4_timestamp_high = -1;
  sGopParamsIp.u4_timestamp_low = -1;

  sGopParamsIp.u4_size = sizeof(ive_ctl_set_gop_params_ip_t);
  sGopParamsOp.u4_size = sizeof(ive_ctl_set_gop_params_op_t);

  ive_api_function(mCodecCtx, &sGopParamsIp, &sGopParamsOp);
  return;
}

void Codec::setProfileParams() {
  ive_ctl_set_profile_params_ip_t sProfileParamsIp{};
  ive_ctl_set_profile_params_op_t sProfileParamsOp{};

  sProfileParamsIp.e_cmd = IVE_CMD_VIDEO_CTL;
  sProfileParamsIp.e_sub_cmd = IVE_CMD_CTL_SET_PROFILE_PARAMS;

  sProfileParamsIp.e_profile = mProfile;
  if (sProfileParamsIp.e_profile == IV_PROFILE_BASE) {
    sProfileParamsIp.u4_entropy_coding_mode = 0;
  } else {
    sProfileParamsIp.u4_entropy_coding_mode = 1;
  }
  sProfileParamsIp.u4_timestamp_high = -1;
  sProfileParamsIp.u4_timestamp_low = -1;

  sProfileParamsIp.u4_size = sizeof(ive_ctl_set_profile_params_ip_t);
  sProfileParamsOp.u4_size = sizeof(ive_ctl_set_profile_params_op_t);

  ive_api_function(mCodecCtx, &sProfileParamsIp, &sProfileParamsOp);
  return;
}

void Codec::setDeblockParams() {
  ive_ctl_set_deblock_params_ip_t sDeblockParamsIp{};
  ive_ctl_set_deblock_params_op_t sDeblockParamsOp{};

  sDeblockParamsIp.e_cmd = IVE_CMD_VIDEO_CTL;
  sDeblockParamsIp.e_sub_cmd = IVE_CMD_CTL_SET_DEBLOCK_PARAMS;

  sDeblockParamsIp.u4_disable_deblock_level = mDisableDeblockLevel;

  sDeblockParamsIp.u4_timestamp_high = -1;
  sDeblockParamsIp.u4_timestamp_low = -1;

  sDeblockParamsIp.u4_size = sizeof(ive_ctl_set_deblock_params_ip_t);
  sDeblockParamsOp.u4_size = sizeof(ive_ctl_set_deblock_params_op_t);

  ive_api_function(mCodecCtx, &sDeblockParamsIp, &sDeblockParamsOp);
  return;
}

void Codec::setVuiParams() {
  ih264e_vui_ip_t sVuiParamsIp{};
  ih264e_vui_op_t sVuiParamsOp{};

  sVuiParamsIp.e_cmd = IVE_CMD_VIDEO_CTL;
  sVuiParamsIp.e_sub_cmd = IVE_CMD_CTL_SET_VUI_PARAMS;

  sVuiParamsIp.u1_aspect_ratio_info_present_flag = mAspectRatioFlag;
  sVuiParamsIp.u1_aspect_ratio_idc = 0;
  sVuiParamsIp.u2_sar_width = 0;
  sVuiParamsIp.u2_sar_height = 0;
  sVuiParamsIp.u1_overscan_info_present_flag = 0;
  sVuiParamsIp.u1_overscan_appropriate_flag = 0;
  sVuiParamsIp.u1_video_signal_type_present_flag = 1;
  sVuiParamsIp.u1_video_format = 0;
  sVuiParamsIp.u1_video_full_range_flag = 0;
  sVuiParamsIp.u1_colour_description_present_flag = 1;
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

  sVuiParamsIp.u4_size = sizeof(ih264e_vui_ip_t);
  sVuiParamsOp.u4_size = sizeof(ih264e_vui_op_t);

  ive_api_function(mCodecCtx, &sVuiParamsIp, &sVuiParamsOp);
  return;
}

void Codec::setSeiMdcvParams() {
  ih264e_ctl_set_sei_mdcv_params_ip_t sSeiMdcvParamsIp{};
  ih264e_ctl_set_sei_mdcv_params_op_t sSeiMdcvParamsOp{};

  sSeiMdcvParamsIp.e_cmd = IVE_CMD_VIDEO_CTL;
  sSeiMdcvParamsIp.e_sub_cmd = IVE_CMD_CTL_SET_SEI_MDCV_PARAMS;
  sSeiMdcvParamsIp.u1_sei_mdcv_params_present_flag = mSeiMdcvFlag;
  if (mSeiMdcvFlag) {
    for (int i4_count = 0; i4_count < NUM_SEI_MDCV_PRIMARIES; ++i4_count) {
      sSeiMdcvParamsIp.au2_display_primaries_x[i4_count] = 30000;
      sSeiMdcvParamsIp.au2_display_primaries_y[i4_count] = 35000;
    }
    sSeiMdcvParamsIp.u2_white_point_x = 30000;
    sSeiMdcvParamsIp.u2_white_point_y = 35000;
    sSeiMdcvParamsIp.u4_max_display_mastering_luminance = 100000000;
    sSeiMdcvParamsIp.u4_min_display_mastering_luminance = 50000;
  }

  sSeiMdcvParamsIp.u4_timestamp_high = -1;
  sSeiMdcvParamsIp.u4_timestamp_low = -1;

  sSeiMdcvParamsIp.u4_size = sizeof(ih264e_ctl_set_sei_mdcv_params_ip_t);
  sSeiMdcvParamsOp.u4_size = sizeof(ih264e_ctl_set_sei_mdcv_params_op_t);
  ih264e_api_function(mCodecCtx, &sSeiMdcvParamsIp, &sSeiMdcvParamsOp);
  return;
}

void Codec::setSeiCllParams() {
  ih264e_ctl_set_sei_cll_params_ip_t sSeiCllParamsIp{};
  ih264e_ctl_set_sei_cll_params_op_t sSeiCllParamsOp{};

  sSeiCllParamsIp.e_cmd = IVE_CMD_VIDEO_CTL;
  sSeiCllParamsIp.e_sub_cmd = IVE_CMD_CTL_SET_SEI_CLL_PARAMS;
  sSeiCllParamsIp.u1_sei_cll_params_present_flag = mSeiCllFlag;
  if (mSeiCllFlag) {
    sSeiCllParamsIp.u2_max_content_light_level = 0;
    sSeiCllParamsIp.u2_max_pic_average_light_level = 0;
  }

  sSeiCllParamsIp.u4_timestamp_high = -1;
  sSeiCllParamsIp.u4_timestamp_low = -1;

  sSeiCllParamsIp.u4_size = sizeof(ih264e_ctl_set_sei_cll_params_ip_t);
  sSeiCllParamsOp.u4_size = sizeof(ih264e_ctl_set_sei_cll_params_op_t);

  ih264e_api_function(mCodecCtx, &sSeiCllParamsIp, &sSeiCllParamsOp);
  return;
}

void Codec::setSeiAveParams() {
  ih264e_ctl_set_sei_ave_params_ip_t sSeiAveParamsIp{};
  ih264e_ctl_set_sei_ave_params_op_t sSeiAveParamsOp{};

  sSeiAveParamsIp.e_cmd = IVE_CMD_VIDEO_CTL;
  sSeiAveParamsIp.e_sub_cmd = IVE_CMD_CTL_SET_SEI_AVE_PARAMS;
  sSeiAveParamsIp.u1_sei_ave_params_present_flag = mSeiAveFlag;
  if (mSeiAveFlag) {
    sSeiAveParamsIp.u4_ambient_illuminance = 1;
    sSeiAveParamsIp.u2_ambient_light_x = 0;
    sSeiAveParamsIp.u2_ambient_light_y = 0;
  }

  sSeiAveParamsIp.u4_timestamp_high = -1;
  sSeiAveParamsIp.u4_timestamp_low = -1;

  sSeiAveParamsIp.u4_size = sizeof(ih264e_ctl_set_sei_ave_params_ip_t);
  sSeiAveParamsOp.u4_size = sizeof(ih264e_ctl_set_sei_ave_params_op_t);

  ih264e_api_function(mCodecCtx, &sSeiAveParamsIp, &sSeiAveParamsOp);
  return;
}

void Codec::setSeiCcvParams() {
  ih264e_ctl_set_sei_ccv_params_ip_t sSeiCcvParamsIp{};
  ih264e_ctl_set_sei_ccv_params_op_t sSeiCcvParamsOp{};

  sSeiCcvParamsIp.e_cmd = IVE_CMD_VIDEO_CTL;
  sSeiCcvParamsIp.e_sub_cmd = IVE_CMD_CTL_SET_SEI_CCV_PARAMS;
  sSeiCcvParamsIp.u1_sei_ccv_params_present_flag = mSeiCcvFlag;
  if (mSeiCcvFlag) {
    sSeiCcvParamsIp.u1_ccv_cancel_flag = 0;
    sSeiCcvParamsIp.u1_ccv_persistence_flag = 1;
    sSeiCcvParamsIp.u1_ccv_primaries_present_flag = 1;
    sSeiCcvParamsIp.u1_ccv_min_luminance_value_present_flag = 1;
    sSeiCcvParamsIp.u1_ccv_max_luminance_value_present_flag = 1;
    sSeiCcvParamsIp.u1_ccv_avg_luminance_value_present_flag = 1;
    sSeiCcvParamsIp.u1_ccv_reserved_zero_2bits = 0;
    for (int i4_count = 0; i4_count < NUM_SEI_CCV_PRIMARIES; ++i4_count) {
      sSeiCcvParamsIp.ai4_ccv_primaries_x[i4_count] = 1;
      sSeiCcvParamsIp.ai4_ccv_primaries_y[i4_count] = 1;
    }
    sSeiCcvParamsIp.u4_ccv_min_luminance_value = 1;
    sSeiCcvParamsIp.u4_ccv_max_luminance_value = 1;
    sSeiCcvParamsIp.u4_ccv_avg_luminance_value = 1;
  }

  sSeiCcvParamsIp.u4_timestamp_high = -1;
  sSeiCcvParamsIp.u4_timestamp_low = -1;

  sSeiCcvParamsIp.u4_size = sizeof(ih264e_ctl_set_sei_ccv_params_ip_t);
  sSeiCcvParamsOp.u4_size = sizeof(ih264e_ctl_set_sei_ccv_params_op_t);

  ih264e_api_function(mCodecCtx, &sSeiCcvParamsIp, &sSeiCcvParamsOp);
  return;
}

void Codec::setSeiSiiParams() {
  ih264e_ctl_set_sei_sii_params_ip_t sSeiSiiParamsIp{};
  ih264e_ctl_set_sei_sii_params_op_t sSeiSiiParamsOp{};

  sSeiSiiParamsIp.e_cmd = IVE_CMD_VIDEO_CTL;
  sSeiSiiParamsIp.e_sub_cmd = IVE_CMD_CTL_SET_SEI_SII_PARAMS;
  sSeiSiiParamsIp.u1_shutter_interval_info_present_flag = mSeiSiiFlag;
  if (mSeiSiiFlag) {
    sSeiSiiParamsIp.u4_sii_sub_layer_idx = 0;
    sSeiSiiParamsIp.u1_shutter_interval_info_present_flag = 1;
    sSeiSiiParamsIp.u4_sii_time_scale = 24000000;
    sSeiSiiParamsIp.u1_fixed_shutter_interval_within_cvs_flag = 0;
    sSeiSiiParamsIp.u4_sii_num_units_in_shutter_interval = 480000;
    sSeiSiiParamsIp.u1_sii_max_sub_layers_minus1 = 7;
    for (int count = 0; count <= sSeiSiiParamsIp.u1_sii_max_sub_layers_minus1; ++count) {
      sSeiSiiParamsIp.au4_sub_layer_num_units_in_shutter_interval[count] = 480000;
    }
    sSeiSiiParamsIp.au4_sub_layer_num_units_in_shutter_interval[sSeiSiiParamsIp.u1_sii_max_sub_layers_minus1] = 240000;
  }

  sSeiSiiParamsIp.u4_timestamp_high = -1;
  sSeiSiiParamsIp.u4_timestamp_low = -1;

  sSeiSiiParamsIp.u4_size = sizeof(ih264e_ctl_set_sei_sii_params_ip_t);
  sSeiSiiParamsOp.u4_size = sizeof(ih264e_ctl_set_sei_sii_params_op_t);

  ih264e_api_function(mCodecCtx, &sSeiSiiParamsIp, &sSeiSiiParamsOp);
  return;
}

void Codec::logVersion() {
  ive_ctl_getversioninfo_ip_t sCtlIp{};
  ive_ctl_getversioninfo_op_t sCtlOp{};
  UWORD8 au1Buf[512];

  sCtlIp.e_cmd = IVE_CMD_VIDEO_CTL;
  sCtlIp.e_sub_cmd = IVE_CMD_CTL_GETVERSION;

  sCtlIp.u4_size = sizeof(ive_ctl_getversioninfo_ip_t);
  sCtlOp.u4_size = sizeof(ive_ctl_getversioninfo_op_t);
  sCtlIp.pu1_version = au1Buf;
  sCtlIp.u4_version_bufsize = sizeof(au1Buf);

  ive_api_function(mCodecCtx, (void *)&sCtlIp, (void *)&sCtlOp);
  return;
}

void Codec::encodeFrames(const uint8_t *data, size_t size) {
  size_t frameSize = (mIvVideoColorFormat == IV_YUV_422ILE) ? (mWidth * mHeight * 2) : ((mWidth * mHeight * 3) / 2);
  ive_video_encode_ip_t sEncodeIp{};
  ive_video_encode_op_t sEncodeOp{};
  uint8_t header[kHeaderLength];
  int32_t numEncodeCalls = 0;
  iv_raw_buf_t *psInpRawBuf = &sEncodeIp.s_inp_buf;
  sEncodeIp.s_out_buf.pv_buf = header;
  sEncodeIp.s_out_buf.u4_bytes = 0;
  sEncodeIp.s_out_buf.u4_bufsize = kHeaderLength;
  sEncodeIp.u4_size = sizeof(ive_video_encode_ip_t);
  sEncodeOp.u4_size = sizeof(ive_video_encode_op_t);

  sEncodeIp.e_cmd = IVE_CMD_VIDEO_ENCODE;
  sEncodeIp.pv_bufs = nullptr;
  sEncodeIp.pv_mb_info = nullptr;
  sEncodeIp.pv_pic_info = nullptr;
  sEncodeIp.u4_mb_info_type = 0;
  sEncodeIp.u4_pic_info_type = 0;
  sEncodeOp.s_out_buf.pv_buf = nullptr;

  /* Initialize color formats */
  memset(psInpRawBuf, 0, sizeof(iv_raw_buf_t));
  psInpRawBuf->u4_size = sizeof(iv_raw_buf_t);
  psInpRawBuf->e_color_fmt = mIvVideoColorFormat;

  ive_api_function(mCodecCtx, &sEncodeIp, &sEncodeOp);
  size_t numFrame = 0;
  std::vector<bufferPtrs> inBuffers;
  uint64_t outputBufferSize = (frameSize / kCompressionRatio);
  while (!sEncodeOp.u4_is_last && numEncodeCalls < kMaxNumEncodeCalls) {
    uint8_t *outputBuffer = (uint8_t *)malloc(outputBufferSize);
    sEncodeIp.s_out_buf.pv_buf = outputBuffer;
    sEncodeIp.s_out_buf.u4_bufsize = outputBufferSize;
    if (size > 0) {
      uint8_t *tmpData = (uint8_t *)malloc(frameSize);
      size_t bytesConsumed = std::min(size, frameSize);
      if (bytesConsumed < frameSize) {
        memset(&tmpData[bytesConsumed], data[0], frameSize - bytesConsumed);
      }
      memcpy(tmpData, data, bytesConsumed);
      bufferPtrs inBuffer = setEncParams(psInpRawBuf, tmpData, frameSize);
      inBuffers.push_back(inBuffer);
      free(tmpData);
      sEncodeIp.u4_is_last = 0;
      if (mSendEosWithLastFrame && size == bytesConsumed) {
        sEncodeIp.u4_is_last = 1;
      }
      if (mIsForceIdrEnabled) {
        if (numFrame == mForceIdrInterval) {
          setFrameType(IV_IDR_FRAME);
        }
      }
      if (mIsDynamicBitRateChangeEnabled) {
        if (numFrame == mDynamicBitRateInterval) {
          if (data[0] & 0x01) {
            mBitrate *= 2;
          } else {
            mBitrate /= 2;
          }
          setBitRate();
        }
      }
      if (mIsDynamicFrameRateChangeEnabled) {
        if (numFrame == mDynamicFrameRateInterval) {
          if (size > 1 && data[1] & 0x01) {
            mFrameRate *= 2;
          } else {
            mFrameRate /= 2;
          }
          setFrameRate();
        }
      }
      ++numFrame;
      data += bytesConsumed;
      size -= bytesConsumed;
    } else {
      sEncodeIp.u4_is_last = 1;
      psInpRawBuf->apv_bufs[0] = nullptr;
      psInpRawBuf->apv_bufs[1] = nullptr;
      psInpRawBuf->apv_bufs[2] = nullptr;
    }
    ive_api_function(mCodecCtx, &sEncodeIp, &sEncodeOp);
    if (sEncodeOp.s_inp_buf.apv_bufs[0]) {
      std::vector<bufferPtrs>::iterator iter;
      uint8_t *inputbuf = (uint8_t *)sEncodeOp.s_inp_buf.apv_bufs[0];
      iter = std::find_if(inBuffers.begin(), inBuffers.end(), [=, &inputbuf](const bufferPtrs &buf) { return std::get<0>(buf) == inputbuf; });
      if (iter != inBuffers.end()) {
        inBuffers.erase(iter);
        free(sEncodeOp.s_inp_buf.apv_bufs[0]);
        if (sEncodeOp.s_inp_buf.apv_bufs[1]) {
          free(sEncodeOp.s_inp_buf.apv_bufs[1]);
        }
        if (sEncodeOp.s_inp_buf.apv_bufs[2]) {
          free(sEncodeOp.s_inp_buf.apv_bufs[2]);
        }
      }
    }
    ++numEncodeCalls;
    free(outputBuffer);
  }
  for (const auto &buffer : inBuffers) {
    free(std::get<0>(buffer));
    if (std::get<1>(buffer)) {
      free(std::get<1>(buffer));
    }
    if (std::get<2>(buffer)) {
      free(std::get<2>(buffer));
    }
  }
  inBuffers.clear();
}

bufferPtrs Codec::setEncParams(iv_raw_buf_t *psInpRawBuf, const uint8_t *data, size_t frameSize) {
  bufferPtrs inBuffer;
  switch (mIvVideoColorFormat) {
  case IV_YUV_420SP_UV:
    [[fallthrough]];
  case IV_YUV_420SP_VU: {
    uint8_t *yPlane = (uint8_t *)malloc(mWidth * mHeight);
    uint8_t *uPlane = (uint8_t *)malloc(frameSize - (mWidth * mHeight));
    memcpy(yPlane, data, mWidth * mHeight);
    memcpy(uPlane, data + (mWidth * mHeight), frameSize - (mWidth * mHeight));
    int32_t yStride = mWidth;
    int32_t uStride = mWidth / 2;
    psInpRawBuf->apv_bufs[0] = yPlane;
    psInpRawBuf->apv_bufs[1] = uPlane;

    psInpRawBuf->au4_wd[0] = mWidth;
    psInpRawBuf->au4_wd[1] = mWidth;

    psInpRawBuf->au4_ht[0] = mHeight;
    psInpRawBuf->au4_ht[1] = mHeight / 2;

    psInpRawBuf->au4_strd[0] = yStride;
    psInpRawBuf->au4_strd[1] = uStride;
    inBuffer = std::make_tuple(yPlane, uPlane, nullptr);
    break;
  }
  case IV_YUV_422ILE: {
    uint8_t *yPlane = (uint8_t *)malloc(frameSize);
    memcpy(yPlane, data, frameSize);
    psInpRawBuf->apv_bufs[0] = yPlane;

    psInpRawBuf->au4_wd[0] = mWidth * 2;

    psInpRawBuf->au4_ht[0] = mHeight;

    psInpRawBuf->au4_strd[0] = mWidth * 2;
    inBuffer = std::make_tuple(yPlane, nullptr, nullptr);
    break;
  }
  case IV_YUV_420P:
    [[fallthrough]];
  default: {
    uint8_t *yPlane = (uint8_t *)malloc(mWidth * mHeight);
    uint8_t *uPlane = (uint8_t *)malloc((mWidth * mHeight) / 4);
    uint8_t *vPlane = (uint8_t *)malloc(frameSize - ((mWidth * mHeight) * 5) / 4);
    memcpy(yPlane, data, mWidth * mHeight);
    memcpy(uPlane, data + (mWidth * mHeight), (mWidth * mHeight) / 4);
    memcpy(vPlane, data + ((mWidth * mHeight) * 5) / 4, frameSize - ((mWidth * mHeight) * 5) / 4);
    int32_t yStride = mWidth;
    int32_t uStride = mWidth / 2;
    int32_t vStride = mWidth / 2;

    psInpRawBuf->apv_bufs[0] = yPlane;
    psInpRawBuf->apv_bufs[1] = uPlane;
    psInpRawBuf->apv_bufs[2] = vPlane;

    psInpRawBuf->au4_wd[0] = mWidth;
    psInpRawBuf->au4_wd[1] = mWidth / 2;
    psInpRawBuf->au4_wd[2] = mWidth / 2;

    psInpRawBuf->au4_ht[0] = mHeight;
    psInpRawBuf->au4_ht[1] = mHeight / 2;
    psInpRawBuf->au4_ht[2] = mHeight / 2;

    psInpRawBuf->au4_strd[0] = yStride;
    psInpRawBuf->au4_strd[1] = uStride;
    psInpRawBuf->au4_strd[2] = vStride;
    inBuffer = std::make_tuple(yPlane, uPlane, vPlane);
    break;
  }
  }
  return inBuffer;
}

void Codec::deInitEncoder() {
  iv_mem_rec_t *ps_mem_rec = mMemRecords;
  for (size_t i = 0; i < mNumMemRecords; ++i) {
    if (ps_mem_rec) {
      free(ps_mem_rec->pv_base);
    }
    ++ps_mem_rec;
  }
  if (mMemRecords) {
    free(mMemRecords);
  }
  mCodecCtx = nullptr;
  return;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < IDX_LAST) {
    return 0;
  }
  Codec *codec = new Codec();
  if (codec->initEncoder(&data, &size)) {
    codec->encodeFrames(data, size);
  }
  delete codec;
  return 0;
}
