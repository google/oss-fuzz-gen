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

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <memory>

#include "ih264_typedefs.h"
#include "ih264d.h"
#include "iv.h"
#include "ivd.h"

#define NELEMENTS(x) (sizeof(x) / sizeof(x[0]))
#define ivd_api_function ih264d_api_function
const IV_COLOR_FORMAT_T supportedColorFormats[] = {IV_YUV_420P, IV_YUV_420SP_UV, IV_YUV_420SP_VU, IV_YUV_422ILE, IV_RGB_565, IV_RGBA_8888};

/* Decoder ignores invalid arch, i.e. for arm build, if SSSE3 is requested,
 * decoder defaults to a supported configuration. So same set of supported
 * architectures can be used in arm/arm64/x86 builds */
const IVD_ARCH_T supportedArchitectures[] = {ARCH_ARM_NONEON, ARCH_ARM_A9Q, ARCH_ARM_NEONINTR, ARCH_ARMV8_GENERIC, ARCH_X86_GENERIC, ARCH_X86_SSSE3, ARCH_X86_SSE42};

enum {
  OFFSET_COLOR_FORMAT = 6,
  OFFSET_NUM_CORES,
  OFFSET_ARCH,
  /* Should be the last entry */
  OFFSET_MAX,
};

const static int kMaxNumDecodeCalls = 100;
const static int kSupportedColorFormats = NELEMENTS(supportedColorFormats);
const static int kSupportedArchitectures = NELEMENTS(supportedArchitectures);
const static int kMaxCores = 4;
void *iv_aligned_malloc(void *ctxt, WORD32 alignment, WORD32 size) {
  void *buf = NULL;
  (void)ctxt;
  if (0 != posix_memalign(&buf, alignment, size)) {
    return NULL;
  }
  return buf;
}

void iv_aligned_free(void *ctxt, void *buf) {
  (void)ctxt;
  free(buf);
}

class Codec {
public:
  Codec(IV_COLOR_FORMAT_T colorFormat, size_t numCores);
  ~Codec();

  void createCodec();
  void deleteCodec();
  void resetCodec();
  void setCores();
  void allocFrame();
  void freeFrame();
  void decodeHeader(const uint8_t *data, size_t size);
  IV_API_CALL_STATUS_T decodeFrame(const uint8_t *data, size_t size, size_t *bytesConsumed);
  void setParams(IVD_VIDEO_DECODE_MODE_T mode);
  void setArchitecture(IVD_ARCH_T arch);

private:
  IV_COLOR_FORMAT_T mColorFormat;
  size_t mNumCores;
  iv_obj_t *mCodec;
  ivd_out_bufdesc_t mOutBufHandle;
  uint32_t mWidth;
  uint32_t mHeight;
};

Codec::Codec(IV_COLOR_FORMAT_T colorFormat, size_t numCores) {
  mColorFormat = colorFormat;
  mNumCores = numCores;
  mCodec = nullptr;
  mWidth = 0;
  mHeight = 0;

  memset(&mOutBufHandle, 0, sizeof(mOutBufHandle));
}
Codec::~Codec() {}
void Codec::createCodec() {
  IV_API_CALL_STATUS_T ret;
  ih264d_create_ip_t create_ip{};
  ih264d_create_op_t create_op{};
  void *fxns = (void *)&ivd_api_function;

  create_ip.s_ivd_create_ip_t.e_cmd = IVD_CMD_CREATE;
  create_ip.s_ivd_create_ip_t.u4_share_disp_buf = 0;
  create_ip.s_ivd_create_ip_t.e_output_format = mColorFormat;
  create_ip.s_ivd_create_ip_t.pf_aligned_alloc = iv_aligned_malloc;
  create_ip.s_ivd_create_ip_t.pf_aligned_free = iv_aligned_free;
  create_ip.u4_keep_threads_active = 1;
  create_ip.s_ivd_create_ip_t.pv_mem_ctxt = NULL;
  create_ip.s_ivd_create_ip_t.u4_size = sizeof(ih264d_create_ip_t);
  create_op.s_ivd_create_op_t.u4_size = sizeof(ih264d_create_op_t);

  ret = ivd_api_function(NULL, (void *)&create_ip, (void *)&create_op);
  if (ret != IV_SUCCESS) {
    return;
  }
  mCodec = (iv_obj_t *)create_op.s_ivd_create_op_t.pv_handle;
  mCodec->pv_fxns = fxns;
  mCodec->u4_size = sizeof(iv_obj_t);
}

void Codec::deleteCodec() {
  ivd_delete_ip_t delete_ip{};
  ivd_delete_op_t delete_op{};

  delete_ip.e_cmd = IVD_CMD_DELETE;
  delete_ip.u4_size = sizeof(ivd_delete_ip_t);
  delete_op.u4_size = sizeof(ivd_delete_op_t);

  ivd_api_function(mCodec, (void *)&delete_ip, (void *)&delete_op);
}
void Codec::resetCodec() {
  ivd_ctl_reset_ip_t s_ctl_ip{};
  ivd_ctl_reset_op_t s_ctl_op{};

  s_ctl_ip.e_cmd = IVD_CMD_VIDEO_CTL;
  s_ctl_ip.e_sub_cmd = IVD_CMD_CTL_RESET;
  s_ctl_ip.u4_size = sizeof(ivd_ctl_reset_ip_t);
  s_ctl_op.u4_size = sizeof(ivd_ctl_reset_op_t);

  ivd_api_function(mCodec, (void *)&s_ctl_ip, (void *)&s_ctl_op);
}

void Codec::setCores() {
  ih264d_ctl_set_num_cores_ip_t s_ctl_ip{};
  ih264d_ctl_set_num_cores_op_t s_ctl_op{};

  s_ctl_ip.e_cmd = IVD_CMD_VIDEO_CTL;
  s_ctl_ip.e_sub_cmd = (IVD_CONTROL_API_COMMAND_TYPE_T)IH264D_CMD_CTL_SET_NUM_CORES;
  s_ctl_ip.u4_num_cores = mNumCores;
  s_ctl_ip.u4_size = sizeof(ih264d_ctl_set_num_cores_ip_t);
  s_ctl_op.u4_size = sizeof(ih264d_ctl_set_num_cores_op_t);

  ivd_api_function(mCodec, (void *)&s_ctl_ip, (void *)&s_ctl_op);
}

void Codec::setParams(IVD_VIDEO_DECODE_MODE_T mode) {
  ivd_ctl_set_config_ip_t s_ctl_ip{};
  ivd_ctl_set_config_op_t s_ctl_op{};

  s_ctl_ip.u4_disp_wd = 0;
  s_ctl_ip.e_frm_skip_mode = IVD_SKIP_NONE;
  s_ctl_ip.e_frm_out_mode = IVD_DISPLAY_FRAME_OUT;
  s_ctl_ip.e_vid_dec_mode = mode;
  s_ctl_ip.e_cmd = IVD_CMD_VIDEO_CTL;
  s_ctl_ip.e_sub_cmd = IVD_CMD_CTL_SETPARAMS;
  s_ctl_ip.u4_size = sizeof(ivd_ctl_set_config_ip_t);
  s_ctl_op.u4_size = sizeof(ivd_ctl_set_config_op_t);

  ivd_api_function(mCodec, (void *)&s_ctl_ip, (void *)&s_ctl_op);
}

void Codec::setArchitecture(IVD_ARCH_T arch) {
  ih264d_ctl_set_processor_ip_t s_ctl_ip{};
  ih264d_ctl_set_processor_op_t s_ctl_op{};

  s_ctl_ip.e_cmd = IVD_CMD_VIDEO_CTL;
  s_ctl_ip.e_sub_cmd = (IVD_CONTROL_API_COMMAND_TYPE_T)IH264D_CMD_CTL_SET_PROCESSOR;
  s_ctl_ip.u4_arch = arch;
  s_ctl_ip.u4_soc = SOC_GENERIC;
  s_ctl_ip.u4_size = sizeof(ih264d_ctl_set_processor_ip_t);
  s_ctl_op.u4_size = sizeof(ih264d_ctl_set_processor_op_t);

  ivd_api_function(mCodec, (void *)&s_ctl_ip, (void *)&s_ctl_op);
}
void Codec::freeFrame() {
  for (int i = 0; i < mOutBufHandle.u4_num_bufs; i++) {
    if (mOutBufHandle.pu1_bufs[i]) {
      free(mOutBufHandle.pu1_bufs[i]);
      mOutBufHandle.pu1_bufs[i] = nullptr;
    }
  }
}
void Codec::allocFrame() {
  size_t sizes[4] = {0};
  size_t num_bufs = 0;

  freeFrame();

  memset(&mOutBufHandle, 0, sizeof(mOutBufHandle));

  switch (mColorFormat) {
  case IV_YUV_420SP_UV:
    [[fallthrough]];
  case IV_YUV_420SP_VU:
    sizes[0] = mWidth * mHeight;
    sizes[1] = mWidth * mHeight >> 1;
    num_bufs = 2;
    break;
  case IV_YUV_422ILE:
    sizes[0] = mWidth * mHeight * 2;
    num_bufs = 1;
    break;
  case IV_RGB_565:
    sizes[0] = mWidth * mHeight * 2;
    num_bufs = 1;
    break;
  case IV_RGBA_8888:
    sizes[0] = mWidth * mHeight * 4;
    num_bufs = 1;
    break;
  case IV_YUV_420P:
    [[fallthrough]];
  default:
    sizes[0] = mWidth * mHeight;
    sizes[1] = mWidth * mHeight >> 2;
    sizes[2] = mWidth * mHeight >> 2;
    num_bufs = 3;
    break;
  }
  mOutBufHandle.u4_num_bufs = num_bufs;
  for (int i = 0; i < num_bufs; i++) {
    mOutBufHandle.u4_min_out_buf_size[i] = sizes[i];
    mOutBufHandle.pu1_bufs[i] = (UWORD8 *)iv_aligned_malloc(NULL, 16, sizes[i]);
  }
}
void Codec::decodeHeader(const uint8_t *data, size_t size) {
  setParams(IVD_DECODE_HEADER);

  size_t numDecodeCalls = 0;

  while (size > 0 && numDecodeCalls < kMaxNumDecodeCalls) {
    IV_API_CALL_STATUS_T ret;
    ivd_video_decode_ip_t dec_ip{};
    ivd_video_decode_op_t dec_op{};
    size_t bytes_consumed;

    dec_ip.e_cmd = IVD_CMD_VIDEO_DECODE;
    dec_ip.u4_ts = 0;
    dec_ip.pv_stream_buffer = (void *)data;
    dec_ip.u4_num_Bytes = size;
    dec_ip.u4_size = sizeof(ivd_video_decode_ip_t);
    dec_op.u4_size = sizeof(ivd_video_decode_op_t);

    ret = ivd_api_function(mCodec, (void *)&dec_ip, (void *)&dec_op);

    bytes_consumed = dec_op.u4_num_bytes_consumed;
    /* If no bytes are consumed, then consume 4 bytes to ensure fuzzer proceeds
     * to feed next data */
    if (!bytes_consumed)
      bytes_consumed = 4;

    bytes_consumed = std::min(size, bytes_consumed);

    data += bytes_consumed;
    size -= bytes_consumed;
    numDecodeCalls++;

    mWidth = std::min(dec_op.u4_pic_wd, (UWORD32)10240);
    mHeight = std::min(dec_op.u4_pic_ht, (UWORD32)10240);

    /* Break after successful header decode */
    if (mWidth && mHeight) {
      break;
    }
  }
  /* if width / height are invalid, set them to defaults */
  if (!mWidth)
    mWidth = 1920;
  if (!mHeight)
    mHeight = 1088;
}

IV_API_CALL_STATUS_T Codec::decodeFrame(const uint8_t *data, size_t size, size_t *bytesConsumed) {
  IV_API_CALL_STATUS_T ret;
  ivd_video_decode_ip_t dec_ip{};
  ivd_video_decode_op_t dec_op{};

  dec_ip.e_cmd = IVD_CMD_VIDEO_DECODE;
  dec_ip.u4_ts = 0;
  dec_ip.pv_stream_buffer = (void *)data;
  dec_ip.u4_num_Bytes = size;
  dec_ip.u4_size = sizeof(ivd_video_decode_ip_t);
  dec_ip.s_out_buffer = mOutBufHandle;

  dec_op.u4_size = sizeof(ivd_video_decode_op_t);

  ret = ivd_api_function(mCodec, (void *)&dec_ip, (void *)&dec_op);

  /* In case of change in resolution, reset codec and feed the same data again
   */
  if (IVD_RES_CHANGED == (dec_op.u4_error_code & 0xFF)) {
    resetCodec();
    ret = ivd_api_function(mCodec, (void *)&dec_ip, (void *)&dec_op);
  }
  *bytesConsumed = dec_op.u4_num_bytes_consumed;

  /* If no bytes are consumed, then consume 4 bytes to ensure fuzzer proceeds
   * to feed next data */
  if (!*bytesConsumed)
    *bytesConsumed = 4;

  if (dec_op.u4_pic_wd && dec_op.u4_pic_ht && (mWidth != dec_op.u4_pic_wd || mHeight != dec_op.u4_pic_ht)) {
    mWidth = std::min(dec_op.u4_pic_wd, (UWORD32)10240);
    mHeight = std::min(dec_op.u4_pic_ht, (UWORD32)10240);
    allocFrame();
  }

  return ret;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) {
    return 0;
  }
  size_t colorFormatOfst = std::min((size_t)OFFSET_COLOR_FORMAT, size - 1);
  size_t numCoresOfst = std::min((size_t)OFFSET_NUM_CORES, size - 1);
  size_t architectureOfst = std::min((size_t)OFFSET_ARCH, size - 1);
  size_t architectureIdx = data[architectureOfst] % kSupportedArchitectures;
  IVD_ARCH_T arch = (IVD_ARCH_T)supportedArchitectures[architectureIdx];
  size_t colorFormatIdx = data[colorFormatOfst] % kSupportedColorFormats;
  IV_COLOR_FORMAT_T colorFormat = (IV_COLOR_FORMAT_T)(supportedColorFormats[colorFormatIdx]);
  uint32_t numCores = (data[numCoresOfst] % kMaxCores) + 1;
  size_t numDecodeCalls = 0;
  Codec *codec = new Codec(colorFormat, numCores);
  codec->createCodec();
  codec->setArchitecture(arch);
  codec->setCores();
  codec->decodeHeader(data, size);
  codec->setParams(IVD_DECODE_FRAME);
  codec->allocFrame();

  while (size > 0 && numDecodeCalls < kMaxNumDecodeCalls) {
    IV_API_CALL_STATUS_T ret;
    size_t bytesConsumed;
    ret = codec->decodeFrame(data, size, &bytesConsumed);

    bytesConsumed = std::min(size, bytesConsumed);
    data += bytesConsumed;
    size -= bytesConsumed;
    numDecodeCalls++;
  }

  codec->freeFrame();
  codec->deleteCodec();
  delete codec;
  return 0;
}
