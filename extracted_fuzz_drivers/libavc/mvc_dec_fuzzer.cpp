/******************************************************************************
 *
 * Copyright (C) 2019 The Android Open Source Project
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
#include <cstdio>
#include <cstdlib>
#include <cstring>

#ifdef __cplusplus
extern "C" {
#include "ih264_typedefs.h"
#include "imvcd.h"
}
#endif

#define MAX_NUM_VIEWS 6

#define NUM_COMPONENTS 3

#define NELEMENTS(x) (sizeof(x) / sizeof(x[0]))

typedef enum ARG_OFFSETS_T {
  OFFSET_COLOR_FORMAT = 6,
  OFFSET_NUM_CORES,
  OFFSET_ARCH,
  /* Should be the last entry */
  OFFSET_MAX,
} ARG_OFFSETS_T;

static const IV_COLOR_FORMAT_T supportedColorFormats[] = {IV_YUV_420P};
static const IVD_ARCH_T supportedArchitectures[] = {ARCH_ARM_NEONINTR, ARCH_X86_GENERIC, ARCH_X86_SSSE3, ARCH_X86_SSE42};
static const int kMaxNumDecodeCalls = 1000;
static const int kSupportedColorFormats = NELEMENTS(supportedColorFormats);
static const int kSupportedArchitectures = NELEMENTS(supportedArchitectures);
static const int kMaxCores = 3;

static inline void *mvcd_aligned_malloc(void *pv_ctxt, WORD32 alignment, WORD32 i4_size) {
  void *buf = nullptr;
  (void)pv_ctxt;

  if (0 != posix_memalign(&buf, alignment, i4_size)) {
    return nullptr;
  }

  return buf;
}

static inline void mvcd_aligned_free(void *pv_ctxt, void *pv_buf) {
  (void)pv_ctxt;
  free(pv_buf);
}

class Codec {
public:
  Codec(IV_COLOR_FORMAT_T colorFormat, size_t numCores);
  ~Codec();

  void resetCodec();
  WORD32 allocFrame();
  void freeFrame();
  IV_API_CALL_STATUS_T decodeHeader(const uint8_t *data, size_t size);
  IV_API_CALL_STATUS_T decodeFrame(const uint8_t *data, size_t size, size_t *bytesConsumed);
  void setArchitecture(IVD_ARCH_T arch);
  void setBufInfo();
  void setCores();

  ivd_out_bufdesc_t *getOutBuf() { return &mOutBufHandle; }

  iv_yuv_buf_t *getViewDispBuf(UWORD16 u2_view_id = 0) { return &as_view_disp_bufs[u2_view_id]; }

  UWORD32 getNumViews() { return mBufInfo.s_mvc_buf_info.u2_num_views; }

  iv_obj_t *getCodecHandle() { return mCodec; }

private:
  iv_obj_t *mCodec;
  ivd_out_bufdesc_t mOutBufHandle;
  iv_yuv_buf_t as_view_disp_bufs[MAX_NUM_VIEWS];
  imvcd_get_buf_info_op_t mBufInfo;
  IV_COLOR_FORMAT_T mColorFormat;
  size_t mNumCores;
  uint32_t mWidth;
  uint32_t mHeight;
};

Codec::Codec(IV_COLOR_FORMAT_T colorFormat, size_t numCores) : mCodec(nullptr), mColorFormat(colorFormat), mNumCores(numCores), mWidth(0), mHeight(0) {
  imvcd_create_ip_t s_create_ip;
  imvcd_create_op_t s_create_op;

  s_create_ip.s_ivd_ip.e_cmd = IVD_CMD_CREATE;
  s_create_ip.s_ivd_ip.e_output_format = colorFormat;
  s_create_ip.s_ivd_ip.pf_aligned_alloc = mvcd_aligned_malloc;
  s_create_ip.s_ivd_ip.pf_aligned_free = mvcd_aligned_free;
  s_create_ip.s_ivd_ip.u4_share_disp_buf = 0;
  s_create_ip.s_ivd_ip.pv_mem_ctxt = nullptr;

  s_create_ip.s_ivd_ip.u4_size = sizeof(s_create_ip.s_ivd_ip);
  s_create_op.s_ivd_op.u4_size = sizeof(s_create_op.s_ivd_op);

  imvcd_api_function(NULL, &s_create_ip, &s_create_op);

  mCodec = static_cast<iv_obj_t *>(s_create_op.s_ivd_op.pv_handle);

  setCores();

  memset(getOutBuf(), 0, sizeof(getOutBuf()[0]));
}

Codec::~Codec() {
  imvcd_delete_ip_t s_delete_ip;
  imvcd_delete_op_t s_delete_op;

  s_delete_ip.s_ivd_ip.e_cmd = IVD_CMD_DELETE;

  s_delete_ip.s_ivd_ip.u4_size = sizeof(s_delete_ip.s_ivd_ip);
  s_delete_op.s_ivd_op.u4_size = sizeof(s_delete_op.s_ivd_op);

  imvcd_api_function(mCodec, &s_delete_ip, &s_delete_op);
}

void Codec::setCores() {
  imvcd_set_num_cores_ip_t s_ctl_ip;
  imvcd_set_num_cores_op_t s_ctl_op;

  s_ctl_ip.u4_size = sizeof(s_ctl_ip);
  s_ctl_op.u4_size = sizeof(s_ctl_op);
  s_ctl_ip.e_cmd = IVD_CMD_VIDEO_CTL;
  s_ctl_ip.e_sub_cmd = static_cast<IVD_CONTROL_API_COMMAND_TYPE_T>(IMVCD_CTL_SET_NUM_CORES);
  s_ctl_ip.u4_num_cores = mNumCores;

  imvcd_api_function(mCodec, &s_ctl_ip, &s_ctl_op);
}

void Codec::setArchitecture(IVD_ARCH_T e_arch) {
  imvcd_set_arch_ip_t s_ctl_ip;
  imvcd_set_arch_op_t s_ctl_op;

  s_ctl_ip.u4_size = sizeof(s_ctl_ip);
  s_ctl_op.u4_size = sizeof(s_ctl_op);
  s_ctl_ip.e_cmd = IVD_CMD_VIDEO_CTL;
  s_ctl_ip.e_sub_cmd = static_cast<IVD_CONTROL_API_COMMAND_TYPE_T>(IMVCD_CTL_SET_PROCESSOR);
  s_ctl_ip.e_arch = e_arch;
  s_ctl_ip.e_soc = SOC_GENERIC;

  imvcd_api_function(mCodec, &s_ctl_ip, &s_ctl_op);
}

void Codec::setBufInfo() {
  imvcd_get_buf_info_ip_t s_ctl_ip;
  imvcd_get_buf_info_op_t s_ctl_op;

  s_ctl_ip.s_ivd_ip.u4_size = sizeof(s_ctl_ip.s_ivd_ip);
  s_ctl_op.s_ivd_op.u4_size = sizeof(s_ctl_op.s_ivd_op);
  s_ctl_ip.s_ivd_ip.e_cmd = IVD_CMD_VIDEO_CTL;
  s_ctl_ip.s_ivd_ip.e_sub_cmd = static_cast<IVD_CONTROL_API_COMMAND_TYPE_T>(IVD_CMD_CTL_GETBUFINFO);

  imvcd_api_function(mCodec, &s_ctl_ip, &s_ctl_op);

  mBufInfo = s_ctl_op;
}

WORD32 Codec::allocFrame() {
  if (getNumViews() > MAX_NUM_VIEWS) {
    return IV_FAIL;
  }

  if (mBufInfo.s_ivd_op.u4_min_num_out_bufs < (NUM_COMPONENTS * getNumViews())) {
    return IV_FAIL;
  }

  getOutBuf()->u4_num_bufs = mBufInfo.s_ivd_op.u4_min_num_out_bufs;

  for (UWORD32 i = 0; i < getOutBuf()->u4_num_bufs; i++) {
    getOutBuf()->u4_min_out_buf_size[i] = mBufInfo.s_ivd_op.u4_min_out_buf_size[i];
    getOutBuf()->pu1_bufs[i] = (UWORD8 *)mvcd_aligned_malloc(nullptr, 16, mBufInfo.s_ivd_op.u4_min_out_buf_size[i]);

    if (getOutBuf()->pu1_bufs[i] == nullptr) {
      return IV_FAIL;
    }
  }

  return IV_SUCCESS;
}

void Codec::freeFrame() {
  for (UWORD32 i = 0; i < getOutBuf()->u4_num_bufs; i++) {
    if (getOutBuf()->pu1_bufs[i]) {
      mvcd_aligned_free(nullptr, getOutBuf()->pu1_bufs[i]);
      getOutBuf()->pu1_bufs[i] = nullptr;
    }
  }
}

static void sendDecodeSignal(iv_obj_t *psCodec, IVD_VIDEO_DECODE_MODE_T eDecMode) {
  imvcd_set_config_ip_t s_ctl_ip;
  imvcd_set_config_op_t s_ctl_op;

  s_ctl_ip.s_ivd_ip.u4_size = sizeof(s_ctl_ip.s_ivd_ip);
  s_ctl_op.s_ivd_op.u4_size = sizeof(s_ctl_op.s_ivd_op);
  s_ctl_ip.s_ivd_ip.e_cmd = IVD_CMD_VIDEO_CTL;
  s_ctl_ip.s_ivd_ip.e_sub_cmd = static_cast<IVD_CONTROL_API_COMMAND_TYPE_T>(IVD_CMD_CTL_SETPARAMS);

  s_ctl_ip.s_ivd_ip.e_frm_out_mode = IVD_DISPLAY_FRAME_OUT;
  s_ctl_ip.s_ivd_ip.e_frm_skip_mode = IVD_SKIP_NONE;
  s_ctl_ip.s_ivd_ip.e_vid_dec_mode = eDecMode;

  imvcd_api_function(psCodec, &s_ctl_ip, &s_ctl_op);
}

IV_API_CALL_STATUS_T Codec::decodeHeader(const uint8_t *data, size_t size) {
  IV_API_CALL_STATUS_T ret;

  WORD32 numBytesRemaining = size;

  sendDecodeSignal(mCodec, IVD_DECODE_HEADER);

  while (size > 0) {
    imvcd_video_decode_ip_t s_video_decode_ip;
    imvcd_video_decode_op_t s_video_decode_op;

    UWORD32 u4_num_bytes_dec = 0;

    memset(&s_video_decode_ip, 0, sizeof(s_video_decode_ip));
    memset(&s_video_decode_op, 0, sizeof(s_video_decode_op));

    s_video_decode_ip.s_ivd_ip.e_cmd = IVD_CMD_VIDEO_DECODE;
    s_video_decode_ip.s_ivd_ip.u4_ts = 0;
    s_video_decode_ip.s_ivd_ip.pv_stream_buffer = static_cast<void *>(const_cast<uint8_t *>(data));
    s_video_decode_ip.s_ivd_ip.u4_num_Bytes = numBytesRemaining;
    s_video_decode_ip.s_ivd_ip.s_out_buffer = getOutBuf()[0];
    s_video_decode_op.ps_view_disp_bufs = getViewDispBuf();

    s_video_decode_ip.s_ivd_ip.u4_size = sizeof(s_video_decode_ip.s_ivd_ip);
    s_video_decode_op.s_ivd_op.u4_size = sizeof(s_video_decode_op.s_ivd_op);

    ret = imvcd_api_function(mCodec, &s_video_decode_ip, &s_video_decode_op);

    if (IV_SUCCESS != ret) {
      return IV_FAIL;
    }

    u4_num_bytes_dec = s_video_decode_op.s_ivd_op.u4_num_bytes_consumed;

    data += u4_num_bytes_dec;
    numBytesRemaining -= u4_num_bytes_dec;
    mWidth = s_video_decode_op.s_ivd_op.u4_pic_wd;
    mHeight = s_video_decode_op.s_ivd_op.u4_pic_ht;

    /* Break after successful header decode */
    if (mWidth && mHeight) {
      break;
    }
  }

  /* if width / height are invalid, set them to defaults */
  if (!mWidth) {
    mWidth = 1920;
  }

  if (!mHeight) {
    mHeight = 1080;
  }

  setBufInfo();

  return IV_SUCCESS;
}

IV_API_CALL_STATUS_T Codec::decodeFrame(const uint8_t *data, size_t size, size_t *bytesConsumed) {
  imvcd_video_decode_ip_t s_video_decode_ip;
  imvcd_video_decode_op_t s_video_decode_op;

  IV_API_CALL_STATUS_T ret;

  memset(&s_video_decode_ip, 0, sizeof(s_video_decode_ip));
  memset(&s_video_decode_op, 0, sizeof(s_video_decode_op));

  sendDecodeSignal(mCodec, IVD_DECODE_FRAME);

  s_video_decode_ip.s_ivd_ip.e_cmd = IVD_CMD_VIDEO_DECODE;
  s_video_decode_ip.s_ivd_ip.u4_ts = 0;
  s_video_decode_ip.s_ivd_ip.pv_stream_buffer = static_cast<void *>(const_cast<uint8_t *>(data));
  s_video_decode_ip.s_ivd_ip.u4_num_Bytes = size;
  s_video_decode_ip.s_ivd_ip.s_out_buffer = getOutBuf()[0];
  s_video_decode_op.ps_view_disp_bufs = getViewDispBuf();

  s_video_decode_ip.s_ivd_ip.u4_size = sizeof(s_video_decode_ip.s_ivd_ip);
  s_video_decode_op.s_ivd_op.u4_size = sizeof(s_video_decode_op.s_ivd_op);

  ret = imvcd_api_function(mCodec, &s_video_decode_ip, &s_video_decode_op);

  bytesConsumed[0] = s_video_decode_op.s_ivd_op.u4_num_bytes_consumed;

  if (s_video_decode_op.s_ivd_op.u4_pic_wd && s_video_decode_op.s_ivd_op.u4_pic_ht && ((mWidth != s_video_decode_op.s_ivd_op.u4_pic_wd) || (mHeight != s_video_decode_op.s_ivd_op.u4_pic_ht))) {
    mWidth = s_video_decode_op.s_ivd_op.u4_pic_wd;
    mHeight = s_video_decode_op.s_ivd_op.u4_pic_ht;
    freeFrame();
    allocFrame();
  }

  return ret;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) {
    return 0;
  }

  WORD32 ret;

  size_t colorFormatOfst = std::min((size_t)OFFSET_COLOR_FORMAT, size - 1);
  size_t numCoresOfst = std::min((size_t)OFFSET_NUM_CORES, size - 1);
  size_t architectureOfst = std::min((size_t)OFFSET_ARCH, size - 1);
  size_t architectureIdx = data[architectureOfst] % kSupportedArchitectures;
  size_t colorFormatIdx = data[colorFormatOfst] % kSupportedColorFormats;
  uint32_t numCores = (data[numCoresOfst] % kMaxCores) + 1;
  uint32_t numDecodeCalls = 0;

  IVD_ARCH_T arch = (IVD_ARCH_T)supportedArchitectures[architectureIdx];
  IV_COLOR_FORMAT_T colorFormat = (IV_COLOR_FORMAT_T)(supportedColorFormats[colorFormatIdx]);

  Codec cCodec = Codec(colorFormat, numCores);

  cCodec.setArchitecture(arch);

  ret = cCodec.decodeHeader(data, size);

  if (IV_SUCCESS != ret) {
    return 0;
  }

  ret = cCodec.allocFrame();

  if (IV_SUCCESS != ret) {
    cCodec.freeFrame();

    return 0;
  }

  while ((size > 0) && (numDecodeCalls < kMaxNumDecodeCalls)) {
    size_t bytesConsumed;

    IV_API_CALL_STATUS_T ret = cCodec.decodeFrame(data, size, &bytesConsumed);

    if (ret != IV_SUCCESS) {
      break;
    }

    bytesConsumed = std::min(size, bytesConsumed);
    data += bytesConsumed;
    size -= bytesConsumed;
    numDecodeCalls++;
  }

  cCodec.freeFrame();

  return 0;
}
