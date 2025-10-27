/******************************************************************************
 *
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
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

#include <vector>

#include "ixheaac_error_standards.h"
#include "ixheaac_type_def.h"
#include "ixheaacd_aac_config.h"
#include "ixheaacd_apicmd_standards.h"
#include "ixheaacd_error_handler.h"
#include "ixheaacd_memory_standards.h"

#include "impd_apicmd_standards.h"
#include "impd_drc_config_params.h"

/* 64*-0.25dB = -16 dB below full scale for mobile conf */
#define DRC_DEFAULT_MOBILE_REF_LEVEL 64
/* maximum compression of dynamic range for mobile conf */
#define DRC_DEFAULT_MOBILE_DRC_CUT 127
/* maximum compression of dynamic range for mobile conf */
#define DRC_DEFAULT_MOBILE_DRC_BOOST 127
/* switch for heavy compression for mobile conf */
#define DRC_DEFAULT_MOBILE_DRC_HEAVY 1
/* encoder target level; -1 => the value is unknown, otherwise dB \
             step value (e.g. 64 for -16 dB) */
#define DRC_DEFAULT_MOBILE_ENC_LEVEL (-1)

#define MAX_CHANNEL_COUNT 8

#define MAX_MEM_ALLOCS 100

#define IA_MAX_OUTPUT_PCM_SIZE (3)
#define IA_MAX_USAC_CH (2)
#define IA_MAX_OUT_SAMPLES_PER_FRAME (4096)

#define IA_DRC_DEC_IN_OUT_BUF_SIZE (IA_MAX_USAC_CH * IA_MAX_OUT_SAMPLES_PER_FRAME * IA_MAX_OUTPUT_PCM_SIZE)

class Codec {
public:
  IA_ERRORCODE initDecoder(const uint8_t *data, size_t size, bool isADTS);
  IA_ERRORCODE initXAACDecoder(bool isADTS);
  IA_ERRORCODE initXAACDrc(const uint8_t *data, size_t size);
  IA_ERRORCODE deInitXAACDecoder();
  IA_ERRORCODE deInitMPEGDDDrc();
  IA_ERRORCODE configXAACDecoder(uint8_t *inBuffer, uint32_t inBufferLength, int32_t *bytesConsumed);
  IA_ERRORCODE initMPEGDDDrc();
  int configMPEGDDrc();
  IA_ERRORCODE decodeXAACStream(uint8_t *inBuffer, uint32_t inBufferLength, int32_t *bytesConsumed, int32_t *outBytes);
  IA_ERRORCODE getXAACStreamInfo();
  IA_ERRORCODE setXAACDRCInfo(int32_t drcCut, int32_t drcBoost, int32_t drcRefLevel, int32_t drcHeavyCompression, int32_t drEffectType);

private:
  void *mXheaacCodecHandle;
  void *mMpegDDrcHandle;
  uint32_t mInputBufferSize;
  uint32_t mOutputFrameLength;
  int8_t *mInputBuffer;
  int8_t *mOutputBuffer;
  int32_t mSampFreq;
  int32_t mNumChannels;
  int32_t mPcmWdSz;
  int32_t mChannelMask;
  bool mIsCodecInitialized;
  bool mIsCodecConfigFlushRequired;
  int8_t *mDrcInBuf;
  int8_t *mDrcOutBuf;
  int32_t mMpegDDRCPresent;
  int32_t mDRCFlag;

  std::vector<void *> mMemoryVec;
  std::vector<void *> mDrcMemoryVec;
};

extern "C" IA_ERRORCODE ixheaacd_dec_api(pVOID p_ia_module_obj, WORD32 i_cmd, WORD32 i_idx, pVOID pv_value);
extern "C" IA_ERRORCODE ia_drc_dec_api(pVOID p_ia_module_obj, WORD32 i_cmd, WORD32 i_idx, pVOID pv_value);
extern "C" IA_ERRORCODE ixheaacd_get_config_param(pVOID p_ia_process_api_obj, pWORD32 pi_samp_freq, pWORD32 pi_num_chan, pWORD32 pi_pcm_wd_sz, pWORD32 pi_channel_mask);

IA_ERRORCODE Codec::initXAACDecoder(bool isADTS) {
  /* First part                                        */
  /* Error Handler Init                                */
  /* Get Library Name, Library Version and API Version */
  /* Initialize API structure + Default config set     */
  /* Set config params from user                       */
  /* Initialize memory tables                          */
  /* Get memory information and allocate memory        */

  mInputBufferSize = 0;
  mInputBuffer = nullptr;
  mOutputBuffer = nullptr;
  /* Process struct initing end */

  /* ******************************************************************/
  /* Initialize API structure and set config params to default        */
  /* ******************************************************************/
  /* API size */
  uint32_t pui_api_size;
  /* Get the API size */
  IA_ERRORCODE err_code = ixheaacd_dec_api(nullptr, IA_API_CMD_GET_API_SIZE, 0, &pui_api_size);

  /* Allocate memory for API */
  mXheaacCodecHandle = malloc(pui_api_size);
  if (!mXheaacCodecHandle) {
    return IA_FATAL_ERROR;
  }
  mMemoryVec.push_back(mXheaacCodecHandle);

  /* Set the config params to default values */
  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_INIT, IA_CMD_TYPE_INIT_API_PRE_CONFIG_PARAMS, nullptr);

  /* Get the API size */
  err_code = ia_drc_dec_api(nullptr, IA_API_CMD_GET_API_SIZE, 0, &pui_api_size);

  /* Allocate memory for API */
  mMpegDDrcHandle = malloc(pui_api_size);
  if (!mMpegDDrcHandle) {
    return IA_FATAL_ERROR;
  }
  mMemoryVec.push_back(mMpegDDrcHandle);

  /* Set the config params to default values */
  err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_INIT, IA_CMD_TYPE_INIT_API_PRE_CONFIG_PARAMS, nullptr);

  /* ******************************************************************/
  /* Set config parameters                                            */
  /* ******************************************************************/
  uint32_t ui_mp4_flag = isADTS ? 0 : 1;
  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_SET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_CONFIG_PARAM_ISMP4, &ui_mp4_flag);

  /* ******************************************************************/
  /* Initialize Memory info tables                                    */
  /* ******************************************************************/
  uint32_t ui_proc_mem_tabs_size;
  pVOID pv_alloc_ptr;
  /* Get memory info tables size */
  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_GET_MEMTABS_SIZE, 0, &ui_proc_mem_tabs_size);

  pv_alloc_ptr = malloc(ui_proc_mem_tabs_size);
  if (!pv_alloc_ptr) {
    return IA_FATAL_ERROR;
  }
  mMemoryVec.push_back(pv_alloc_ptr);

  /* Set pointer for process memory tables    */
  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_SET_MEMTABS_PTR, 0, pv_alloc_ptr);

  /* initialize the API, post config, fill memory tables  */
  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_INIT, IA_CMD_TYPE_INIT_API_POST_CONFIG_PARAMS, nullptr);

  /* ******************************************************************/
  /* Allocate Memory with info from library                           */
  /* ******************************************************************/
  /* There are four different types of memories, that needs to be allocated */
  /* persistent,scratch,input and output */
  for (int i = 0; i < 4; i++) {
    int ui_size = 0, ui_alignment = 0, ui_type = 0;

    /* Get memory size */
    err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_GET_MEM_INFO_SIZE, i, &ui_size);

    /* Get memory alignment */
    err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_GET_MEM_INFO_ALIGNMENT, i, &ui_alignment);

    /* Get memory type */
    err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_GET_MEM_INFO_TYPE, i, &ui_type);

    pv_alloc_ptr = NULL;
    ui_alignment = (ui_alignment + sizeof(void *) - 1) / sizeof(void *);
    ui_alignment = ui_alignment * sizeof(void *);
    if (0 != posix_memalign(&pv_alloc_ptr, ui_alignment, ui_size)) {
      return IA_FATAL_ERROR;
    }
    if (!pv_alloc_ptr) {
      return IA_FATAL_ERROR;
    }
    mMemoryVec.push_back(pv_alloc_ptr);

    /* Set the buffer pointer */
    err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_SET_MEM_PTR, i, pv_alloc_ptr);

    if (ui_type == IA_MEMTYPE_INPUT) {
      mInputBuffer = (pWORD8)pv_alloc_ptr;
      mInputBufferSize = ui_size;
    }
    if (ui_type == IA_MEMTYPE_OUTPUT)
      mOutputBuffer = (pWORD8)pv_alloc_ptr;
  }
  /* End first part */

  return IA_NO_ERROR;
}
enum { DRC_TARGET_LEVEL_OFFSET = 6, DRC_ATTENUATION_OFFSET, DRC_BOOST_OFFSET, DRC_COMPRESS_OFFSET, DRC_EFFECT_OFFSET };

IA_ERRORCODE Codec::initXAACDrc(const uint8_t *data, size_t size) {
  IA_ERRORCODE err_code = IA_NO_ERROR;
  unsigned int ui_drc_val;
  //  DRC_PRES_MODE_WRAP_DESIRED_TARGET
  size_t targetLevelOffset = std::min((size_t)DRC_TARGET_LEVEL_OFFSET, size - 1);
  int32_t targetRefLevel = data[targetLevelOffset];

  ui_drc_val = (unsigned int)targetRefLevel;
  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_SET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_CONFIG_PARAM_DRC_TARGET_LEVEL, &ui_drc_val);

  /* Use ui_drc_val from PROP_DRC_OVERRIDE_REF_LEVEL or
   * DRC_DEFAULT_MOBILE_REF_LEVEL
   * for IA_ENHAACPLUS_DEC_DRC_TARGET_LOUDNESS too */
  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_SET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_DRC_TARGET_LOUDNESS, &ui_drc_val);

  size_t attenuationOffset = std::min((size_t)DRC_ATTENUATION_OFFSET, size - 1);
  int32_t attenuationFactor = data[attenuationOffset];

  ui_drc_val = (unsigned int)attenuationFactor;
  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_SET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_CONFIG_PARAM_DRC_CUT, &ui_drc_val);

  //  DRC_PRES_MODE_WRAP_DESIRED_BOOST_FACTOR
  size_t boostOffset = std::min((size_t)DRC_BOOST_OFFSET, size - 1);
  int32_t boostFactor = data[boostOffset];

  ui_drc_val = (unsigned int)boostFactor;
  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_SET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_CONFIG_PARAM_DRC_BOOST, &ui_drc_val);

  //  DRC_PRES_MODE_WRAP_DESIRED_HEAVY
  size_t compressOffset = std::min((size_t)DRC_COMPRESS_OFFSET, size - 1);
  int32_t compressMode = data[compressOffset];
  ui_drc_val = (unsigned int)compressMode;

  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_SET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_CONFIG_PARAM_DRC_HEAVY_COMP, &ui_drc_val);

  // AAC_UNIDRC_SET_EFFECT
  size_t effectOffset = std::min((size_t)DRC_EFFECT_OFFSET, size - 1);
  int32_t effectType = data[effectOffset];
  ui_drc_val = (unsigned int)effectType;
  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_SET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_DRC_EFFECT_TYPE, &ui_drc_val);

  return IA_NO_ERROR;
}

IA_ERRORCODE Codec::deInitXAACDecoder() {
  /* Error code */
  IA_ERRORCODE err_code = IA_NO_ERROR;

  if (mXheaacCodecHandle) {
    /* Tell that the input is over in this buffer */
    err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_INPUT_OVER, 0, nullptr);
  }

  /* Irrespective of error returned in IA_API_CMD_INPUT_OVER, free allocated
   * memory */
  for (void *buf : mMemoryVec) {
    if (buf)
      free(buf);
  }
  mMemoryVec.clear();
  mXheaacCodecHandle = nullptr;

  return err_code;
}

IA_ERRORCODE Codec::deInitMPEGDDDrc() {
  for (void *buf : mDrcMemoryVec) {
    if (buf)
      free(buf);
  }
  mDrcMemoryVec.clear();
  return IA_NO_ERROR;
}

IA_ERRORCODE Codec::configXAACDecoder(uint8_t *inBuffer, uint32_t inBufferLength, int32_t *bytesConsumed) {
  if (mInputBufferSize < inBufferLength) {
    inBufferLength = mInputBufferSize;
  }
  /* Copy the buffer passed by Android plugin to codec input buffer */
  memcpy(mInputBuffer, inBuffer, inBufferLength);

  /* Set number of bytes to be processed */
  IA_ERRORCODE err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_SET_INPUT_BYTES, 0, &inBufferLength);

  if (mIsCodecConfigFlushRequired) {
    /* If codec is already initialized, then GA header is passed again */
    /* Need to call the Flush API instead of INIT_PROCESS */
    mIsCodecInitialized = false; /* Codec needs to be Reinitialized after flush */
    err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_INIT, IA_CMD_TYPE_GA_HDR, nullptr);

  } else {
    /* Initialize the process */
    err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_INIT, IA_CMD_TYPE_INIT_PROCESS, nullptr);
  }

  uint32_t ui_init_done;
  /* Checking for end of initialization */
  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_INIT, IA_CMD_TYPE_INIT_DONE_QUERY, &ui_init_done);

  /* How much buffer is used in input buffers */
  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_GET_CURIDX_INPUT_BUF, 0, bytesConsumed);

  if (ui_init_done) {
    err_code = getXAACStreamInfo();

    mIsCodecInitialized = true;

    err_code = configMPEGDDrc();
  }

  return IA_NO_ERROR;
}
IA_ERRORCODE Codec::initMPEGDDDrc() {
  IA_ERRORCODE err_code = IA_NO_ERROR;

  for (int i = 0; i < (WORD32)2; i++) {
    WORD32 ui_size, ui_alignment, ui_type;
    pVOID pv_alloc_ptr;

    /* Get memory size */
    err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_GET_MEM_INFO_SIZE, i, &ui_size);

    /* Get memory alignment */
    err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_GET_MEM_INFO_ALIGNMENT, i, &ui_alignment);

    /* Get memory type */
    err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_GET_MEM_INFO_TYPE, i, &ui_type);

    pv_alloc_ptr = malloc(ui_size);
    if (pv_alloc_ptr == nullptr) {
      return IA_FATAL_ERROR;
    }
    mDrcMemoryVec.push_back(pv_alloc_ptr);

    /* Set the buffer pointer */
    err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_SET_MEM_PTR, i, pv_alloc_ptr);
  }

  mDrcInBuf = (int8_t *)malloc(IA_DRC_DEC_IN_OUT_BUF_SIZE);
  if (mDrcInBuf == nullptr) {
    return IA_FATAL_ERROR;
  }
  mDrcMemoryVec.push_back(mDrcInBuf);

  err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_SET_MEM_PTR, 2, mDrcInBuf);

  mDrcOutBuf = (int8_t *)malloc(IA_DRC_DEC_IN_OUT_BUF_SIZE);
  if (mDrcOutBuf == nullptr) {
    return IA_FATAL_ERROR;
  }
  mDrcMemoryVec.push_back(mDrcOutBuf);

  err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_SET_MEM_PTR, 3, mDrcOutBuf);

  return IA_NO_ERROR;
}
int Codec::configMPEGDDrc() {
  IA_ERRORCODE err_code = IA_NO_ERROR;
  int i_effect_type;
  int i_loud_norm;
  int i_target_loudness;
  unsigned int i_sbr_mode;
  uint32_t ui_proc_mem_tabs_size = 0;
  pVOID pv_alloc_ptr = NULL;

  /* Sampling Frequency */
  err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_SET_CONFIG_PARAM, IA_DRC_DEC_CONFIG_PARAM_SAMP_FREQ, &mSampFreq);

  /* Total Number of Channels */
  err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_SET_CONFIG_PARAM, IA_DRC_DEC_CONFIG_PARAM_NUM_CHANNELS, &mNumChannels);

  /* PCM word size  */
  err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_SET_CONFIG_PARAM, IA_DRC_DEC_CONFIG_PARAM_PCM_WDSZ, &mPcmWdSz);

  /*Set Effect Type*/
  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_GET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_CONFIG_PARAM_DRC_EFFECT_TYPE, &i_effect_type);

  err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_SET_CONFIG_PARAM, IA_DRC_DEC_CONFIG_DRC_EFFECT_TYPE, &i_effect_type);

  /*Set target loudness */
  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_GET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_CONFIG_PARAM_DRC_TARGET_LOUDNESS, &i_target_loudness);

  err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_SET_CONFIG_PARAM, IA_DRC_DEC_CONFIG_DRC_TARGET_LOUDNESS, &i_target_loudness);

  /*Set loud_norm_flag*/
  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_GET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_CONFIG_PARAM_DRC_LOUD_NORM, &i_loud_norm);

  err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_SET_CONFIG_PARAM, IA_DRC_DEC_CONFIG_DRC_LOUD_NORM, &i_loud_norm);

  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_GET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_CONFIG_PARAM_SBR_MODE, &i_sbr_mode);

  /* Get memory info tables size */
  err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_GET_MEMTABS_SIZE, 0, &ui_proc_mem_tabs_size);

  pv_alloc_ptr = malloc(ui_proc_mem_tabs_size);
  if (pv_alloc_ptr == NULL) {
    return IA_FATAL_ERROR;
  }
  memset(pv_alloc_ptr, 0, ui_proc_mem_tabs_size);
  mMemoryVec.push_back(pv_alloc_ptr);

  /* Set pointer for process memory tables */
  err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_SET_MEMTABS_PTR, 0, pv_alloc_ptr);

  err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_INIT, IA_CMD_TYPE_INIT_API_POST_CONFIG_PARAMS, nullptr);

  /* Free any memory that is allocated for MPEG D Drc so far */
  deInitMPEGDDDrc();

  err_code = initMPEGDDDrc();
  if (err_code != IA_NO_ERROR) {
    deInitMPEGDDDrc();
    return err_code;
  }

  /* DRC buffers
      buf[0] - contains extension element pay load loudness related
      buf[1] - contains extension element pay load*/
  {
    VOID *p_array[2][16];
    WORD32 ii;
    WORD32 buf_sizes[2][16];
    WORD32 num_elements;
    WORD32 num_config_ext;
    WORD32 bit_str_fmt = 1;

    WORD32 uo_num_chan;

    memset(buf_sizes, 0, 32 * sizeof(WORD32));

    err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_GET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_CONFIG_EXT_ELE_BUF_SIZES, &buf_sizes[0][0]);

    err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_GET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_CONFIG_EXT_ELE_PTR, &p_array);

    err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_INIT, IA_CMD_TYPE_INIT_SET_BUFF_PTR, nullptr);

    err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_GET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_CONFIG_NUM_ELE, &num_elements);

    err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_GET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_CONFIG_NUM_CONFIG_EXT, &num_config_ext);

    for (ii = 0; ii < num_config_ext; ii++) {
      /*copy loudness bitstream*/
      if (buf_sizes[0][ii] > 0) {
        memcpy(mDrcInBuf, p_array[0][ii], buf_sizes[0][ii]);

        /*Set bitstream_split_format */
        err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_SET_CONFIG_PARAM, IA_DRC_DEC_CONFIG_PARAM_BITS_FORMAT, &bit_str_fmt);

        /* Set number of bytes to be processed */
        err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_SET_INPUT_BYTES_IL_BS, 0, &buf_sizes[0][ii]);

        /* Execute process */
        err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_INIT, IA_CMD_TYPE_INIT_CPY_IL_BSF_BUFF, nullptr);

        mDRCFlag = 1;
      }
    }

    for (ii = 0; ii < num_elements; ii++) {
      /*copy config bitstream*/
      if (buf_sizes[1][ii] > 0) {
        memcpy(mDrcInBuf, p_array[1][ii], buf_sizes[1][ii]);
        /* Set number of bytes to be processed */

        /*Set bitstream_split_format */
        err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_SET_CONFIG_PARAM, IA_DRC_DEC_CONFIG_PARAM_BITS_FORMAT, &bit_str_fmt);

        err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_SET_INPUT_BYTES_IC_BS, 0, &buf_sizes[1][ii]);

        /* Execute process */
        err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_INIT, IA_CMD_TYPE_INIT_CPY_IC_BSF_BUFF, nullptr);

        mDRCFlag = 1;
      }
    }

    if (mDRCFlag == 1) {
      mMpegDDRCPresent = 1;
    } else {
      mMpegDDRCPresent = 0;
    }

    /*Read interface buffer config file bitstream*/
    if (mMpegDDRCPresent == 1) {
      WORD32 interface_is_present = 1;

      if (i_sbr_mode != 0) {
        if (i_sbr_mode == 1) {
          mOutputFrameLength = 2048;
        } else if (i_sbr_mode == 3) {
          mOutputFrameLength = 4096;
        } else {
          mOutputFrameLength = 1024;
        }
      } else {
        mOutputFrameLength = 4096;
      }

      err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_SET_CONFIG_PARAM, IA_DRC_DEC_CONFIG_PARAM_FRAME_SIZE, (WORD32 *)&mOutputFrameLength);

      err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_SET_CONFIG_PARAM, IA_DRC_DEC_CONFIG_PARAM_INT_PRESENT, &interface_is_present);

      /* Execute process */
      err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_INIT, IA_CMD_TYPE_INIT_CPY_IN_BSF_BUFF, nullptr);

      err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_INIT, IA_CMD_TYPE_INIT_PROCESS, nullptr);

      err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_GET_CONFIG_PARAM, IA_DRC_DEC_CONFIG_PARAM_NUM_CHANNELS, &uo_num_chan);
    }
  }

  return err_code;
}
IA_ERRORCODE Codec::initDecoder(const uint8_t *data, size_t size, bool isADTS) {
  IA_ERRORCODE err_code = IA_NO_ERROR;

  err_code = initXAACDecoder(isADTS);
  if (err_code != IA_NO_ERROR) {
    /* Call deInit to free any allocated memory */
    deInitXAACDecoder();
    return IA_FATAL_ERROR;
  }

  err_code = initXAACDrc(data, size);

  return IA_NO_ERROR;
}
IA_ERRORCODE Codec::decodeXAACStream(uint8_t *inBuffer, uint32_t inBufferLength, int32_t *bytesConsumed, int32_t *outBytes) {
  if (mInputBufferSize < inBufferLength) {
    inBufferLength = mInputBufferSize;
  }
  /* If codec is not initialized, call configXAACDecoder decoder again */
  if (!mIsCodecInitialized) {
    configXAACDecoder(inBuffer, inBufferLength, bytesConsumed);
  }
  /* Copy the buffer passed by Android plugin to codec input buffer */
  memcpy(mInputBuffer, inBuffer, inBufferLength);

  /* Set number of bytes to be processed */
  IA_ERRORCODE err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_SET_INPUT_BYTES, 0, &inBufferLength);

  /* Execute process */
  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_EXECUTE, IA_CMD_TYPE_DO_EXECUTE, nullptr);

  /* Checking for end of processing */
  uint32_t ui_exec_done;
  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_EXECUTE, IA_CMD_TYPE_DONE_QUERY, &ui_exec_done);

  if (ui_exec_done != 1) {
    VOID *p_array;       // ITTIAM:buffer to handle gain payload
    WORD32 buf_size = 0; // ITTIAM:gain payload length
    WORD32 bit_str_fmt = 1;
    WORD32 gain_stream_flag = 1;

    err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_GET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_CONFIG_GAIN_PAYLOAD_LEN, &buf_size);

    err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_GET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_CONFIG_GAIN_PAYLOAD_BUF, &p_array);

    if (buf_size > 0) {
      /*Set bitstream_split_format */
      err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_SET_CONFIG_PARAM, IA_DRC_DEC_CONFIG_PARAM_BITS_FORMAT, &bit_str_fmt);

      memcpy(mDrcInBuf, p_array, buf_size);
      /* Set number of bytes to be processed */
      err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_SET_INPUT_BYTES_BS, 0, &buf_size);

      err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_SET_CONFIG_PARAM, IA_DRC_DEC_CONFIG_GAIN_STREAM_FLAG, &gain_stream_flag);

      /* Execute process */
      err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_INIT, IA_CMD_TYPE_INIT_CPY_BSF_BUFF, nullptr);

      mMpegDDRCPresent = 1;
    }
  }

  /* How much buffer is used in input buffers */
  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_GET_CURIDX_INPUT_BUF, 0, bytesConsumed);

  /* Get the output bytes */
  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_GET_OUTPUT_BYTES, 0, outBytes);

  if (mMpegDDRCPresent == 1) {
    memcpy(mDrcInBuf, mOutputBuffer, *outBytes);
    err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_SET_INPUT_BYTES, 0, outBytes);

    err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_EXECUTE, IA_CMD_TYPE_DO_EXECUTE, nullptr);

    memcpy(mOutputBuffer, mDrcOutBuf, *outBytes);
  }
  return IA_NO_ERROR;
}

IA_ERRORCODE Codec::getXAACStreamInfo() {
  IA_ERRORCODE err_code = IA_NO_ERROR;

  /* Sampling frequency */
  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_GET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_CONFIG_PARAM_SAMP_FREQ, &mSampFreq);

  /* Total Number of Channels */
  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_GET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_CONFIG_PARAM_NUM_CHANNELS, &mNumChannels);

  if (mNumChannels > MAX_CHANNEL_COUNT) {
    return IA_FATAL_ERROR;
  }

  /* PCM word size */
  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_GET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_CONFIG_PARAM_PCM_WDSZ, &mPcmWdSz);

  if ((mPcmWdSz / 8) != 2) {
    return IA_FATAL_ERROR;
  }

  /* channel mask to tell the arrangement of channels in bit stream */
  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_GET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_CONFIG_PARAM_CHANNEL_MASK, &mChannelMask);

  /* Channel mode to tell MONO/STEREO/DUAL-MONO/NONE_OF_THESE */
  uint32_t ui_channel_mode;
  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_GET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_CONFIG_PARAM_CHANNEL_MODE, &ui_channel_mode);

  /* Channel mode to tell SBR PRESENT/NOT_PRESENT */
  uint32_t ui_sbr_mode;
  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_GET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_CONFIG_PARAM_SBR_MODE, &ui_sbr_mode);

  /* mOutputFrameLength = 1024 * (1 + SBR_MODE) for AAC */
  /* For USAC it could be 1024 * 3 , support to query  */
  /* not yet added in codec                            */
  mOutputFrameLength = 1024 * (1 + ui_sbr_mode);

  return IA_NO_ERROR;
}

IA_ERRORCODE Codec::setXAACDRCInfo(int32_t drcCut, int32_t drcBoost, int32_t drcRefLevel, int32_t drcHeavyCompression, int32_t drEffectType) {
  IA_ERRORCODE err_code = IA_NO_ERROR;

  int32_t ui_drc_enable = 1;
  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_SET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_CONFIG_PARAM_DRC_ENABLE, &ui_drc_enable);

  if (drcCut != -1) {
    err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_SET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_CONFIG_PARAM_DRC_CUT, &drcCut);
  }

  if (drcBoost != -1) {
    err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_SET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_CONFIG_PARAM_DRC_BOOST, &drcBoost);
  }

  if (drcRefLevel != -1) {
    err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_SET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_CONFIG_PARAM_DRC_TARGET_LEVEL, &drcRefLevel);
  }

  if (drcRefLevel != -1) {
    err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_SET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_DRC_TARGET_LOUDNESS, &drcRefLevel);
  }

  if (drcHeavyCompression != -1) {
    err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_SET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_CONFIG_PARAM_DRC_HEAVY_COMP, &drcHeavyCompression);
  }

  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_SET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_DRC_EFFECT_TYPE, &drEffectType);

  int32_t i_effect_type, i_target_loudness, i_loud_norm;
  /*Set Effect Type*/
  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_GET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_CONFIG_PARAM_DRC_EFFECT_TYPE, &i_effect_type);

  err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_SET_CONFIG_PARAM, IA_DRC_DEC_CONFIG_DRC_EFFECT_TYPE, &i_effect_type);

  /*Set target loudness */
  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_GET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_CONFIG_PARAM_DRC_TARGET_LOUDNESS, &i_target_loudness);

  err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_SET_CONFIG_PARAM, IA_DRC_DEC_CONFIG_DRC_TARGET_LOUDNESS, &i_target_loudness);

  /*Set loud_norm_flag*/
  err_code = ixheaacd_dec_api(mXheaacCodecHandle, IA_API_CMD_GET_CONFIG_PARAM, IA_ENHAACPLUS_DEC_CONFIG_PARAM_DRC_LOUD_NORM, &i_loud_norm);

  err_code = ia_drc_dec_api(mMpegDDrcHandle, IA_API_CMD_SET_CONFIG_PARAM, IA_DRC_DEC_CONFIG_DRC_LOUD_NORM, &i_loud_norm);

  return IA_NO_ERROR;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int status;
  int num_proc_iterations = 0;
  if (size < 1)
    return 0;
  Codec *codec = new Codec();
  bool isADTS = false;
  if (size >= 2) {
    if ((data[0] == 0xFF) && ((data[1] & 0xF0) == 0xF0)) {
      isADTS = true;
    }
  }
  status = codec->initDecoder(data, size, isADTS);
  if (0 == status) {
    int32_t bytesConsumed = 0;
    status = codec->configXAACDecoder((uint8_t *)data, size, &bytesConsumed);
    while ((int32_t)size > bytesConsumed) {
      int32_t numOutBytes;
      size -= bytesConsumed;
      data += bytesConsumed;
      status = codec->decodeXAACStream((uint8_t *)data, size, &bytesConsumed, &numOutBytes);
      num_proc_iterations++;
      /* Stop processing after 500 frames */
      if (num_proc_iterations > 500)
        break;

      /* If decoder doesn't consume any bytes, advance by 4 bytes */
      if (0 == bytesConsumed)
        bytesConsumed = 4;
    }
  }
  status = codec->deInitXAACDecoder();
  status = codec->deInitMPEGDDDrc();
  delete codec;
  return 0;
}
