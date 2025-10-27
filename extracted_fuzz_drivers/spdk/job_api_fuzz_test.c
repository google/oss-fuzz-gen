/**********************************************************************
  Copyright(c) 2021-2023, Intel Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************/

#include <intel-ipsec-mb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define BUFF_SIZE (32 * 1024 * 1024)
#define MAX_BURST_JOBS 32
#define MAX_SGL_SEGS 32

int LLVMFuzzerTestOneInput(const uint8_t *, size_t);

static int custom_op(struct IMB_JOB *job) {
  (void)job;
  return 0;
}

static void clamp_lengths(struct IMB_JOB *job, const uint64_t buffsize) {
  if (job->msg_len_to_cipher_in_bytes > buffsize)
    job->msg_len_to_cipher_in_bytes = buffsize;

  if (job->msg_len_to_hash_in_bytes > buffsize)
    job->msg_len_to_hash_in_bytes = buffsize;

  if (job->cipher_start_src_offset_in_bytes > buffsize)
    job->cipher_start_src_offset_in_bytes = buffsize;

  if (job->hash_start_src_offset_in_bytes > buffsize)
    job->hash_start_src_offset_in_bytes = buffsize;
}

static void fill_job_sgl_segments(struct IMB_JOB *job, struct IMB_SGL_IOV *sgl_segs, const int num_sgl_segs, void *buff, const uint64_t buffsize) {
  for (int i = 0; i < num_sgl_segs; i++) {
    sgl_segs->in = buff;
    sgl_segs->out = buff;
    sgl_segs->len = buffsize;
  }

  job->sgl_io_segs = sgl_segs;
  job->num_sgl_io_segs = (uint64_t)num_sgl_segs;
}

static void fill_job_data(struct IMB_JOB *job, void *buff) {
  if (job->src != NULL)
    job->src = (uint8_t *)buff;
  if (job->dst != NULL)
    job->dst = (uint8_t *)buff;
  if (job->enc_keys != NULL)
    job->enc_keys = buff;
  if (job->dec_keys != NULL)
    job->dec_keys = buff;
  if (job->iv != NULL)
    job->iv = (uint8_t *)buff;
  if (job->auth_tag_output != NULL)
    job->auth_tag_output = (uint8_t *)buff;
}

static void fill_additional_cipher_data(struct IMB_JOB *job, struct IMB_SGL_IOV *sgl_segs, const int num_sgl_segs, void *buff, const uint64_t buffsize) {
  const IMB_CIPHER_MODE cipherMode = job->cipher_mode;

  switch (cipherMode) {
  case IMB_CIPHER_CUSTOM:
    job->cipher_func = custom_op;
    break;
  case IMB_CIPHER_CCM:
    if (job->u.CCM.aad != NULL)
      job->u.CCM.aad = buff;
    if (job->u.CCM.aad_len_in_bytes > buffsize)
      job->u.CCM.aad_len_in_bytes = buffsize;
    break;
  case IMB_CIPHER_GCM:
    if (job->u.GCM.aad != NULL)
      job->u.GCM.aad = buff;
    if (job->u.GCM.aad_len_in_bytes > buffsize)
      job->u.GCM.aad_len_in_bytes = buffsize;
    if (job->iv_len_in_bytes > buffsize)
      job->iv_len_in_bytes = buffsize;
    break;
  case IMB_CIPHER_GCM_SGL:
    if (job->u.GCM.aad != NULL)
      job->u.GCM.aad = buff;
    if (job->u.GCM.ctx != NULL) {
      job->u.GCM.ctx = buff;
      job->u.GCM.ctx->partial_block_length &= 15;
    }
    if (job->u.GCM.aad_len_in_bytes > buffsize)
      job->u.GCM.aad_len_in_bytes = buffsize;
    if (job->iv_len_in_bytes > buffsize)
      job->iv_len_in_bytes = buffsize;
    fill_job_sgl_segments(job, sgl_segs, num_sgl_segs, buff, buffsize);
    break;
  case IMB_CIPHER_CHACHA20_POLY1305:
    if (job->u.CHACHA20_POLY1305.aad != NULL)
      job->u.CHACHA20_POLY1305.aad = buff;
    if (job->u.CHACHA20_POLY1305.aad_len_in_bytes > buffsize)
      job->u.CHACHA20_POLY1305.aad_len_in_bytes = buffsize;
    break;
  case IMB_CIPHER_CHACHA20_POLY1305_SGL:
    if (job->u.CHACHA20_POLY1305.aad != NULL)
      job->u.CHACHA20_POLY1305.aad = buff;
    if (job->u.CHACHA20_POLY1305.ctx != NULL) {
      job->u.CHACHA20_POLY1305.ctx = buff;
      job->u.CHACHA20_POLY1305.ctx->remain_ks_bytes &= 63;
      job->u.CHACHA20_POLY1305.ctx->remain_ct_bytes &= 15;
    }
    if (job->u.CHACHA20_POLY1305.aad_len_in_bytes > buffsize)
      job->u.CHACHA20_POLY1305.aad_len_in_bytes = buffsize;
    fill_job_sgl_segments(job, sgl_segs, num_sgl_segs, buff, buffsize);
    break;
  case IMB_CIPHER_SNOW_V_AEAD:
    if (job->u.SNOW_V_AEAD.aad != NULL)
      job->u.SNOW_V_AEAD.aad = buff;
    if (job->u.SNOW_V_AEAD.reserved != NULL)
      job->u.SNOW_V_AEAD.reserved = buff;
    if (job->u.SNOW_V_AEAD.aad_len_in_bytes > buffsize)
      job->u.SNOW_V_AEAD.aad_len_in_bytes = buffsize;
    break;
  case IMB_CIPHER_CBCS_1_9:
    if (job->cipher_fields.CBCS.next_iv != NULL)
      job->cipher_fields.CBCS.next_iv = buff;
    break;
  default:
    break;
  }
}

static void fill_additional_hash_data(struct IMB_JOB *job, void *buff, uint64_t buffsize) {
  const IMB_HASH_ALG hashMode = job->hash_alg;

  switch (hashMode) {
  case IMB_AUTH_CUSTOM:
    job->hash_func = custom_op;
    break;
  case IMB_AUTH_HMAC_SHA_1:
  case IMB_AUTH_HMAC_SHA_224:
  case IMB_AUTH_HMAC_SHA_256:
  case IMB_AUTH_HMAC_SHA_384:
  case IMB_AUTH_HMAC_SHA_512:
  case IMB_AUTH_MD5:
  case IMB_AUTH_HMAC_SM3:
    if (job->u.HMAC._hashed_auth_key_xor_ipad != NULL)
      job->u.HMAC._hashed_auth_key_xor_ipad = (uint8_t *)buff;
    if (job->u.HMAC._hashed_auth_key_xor_opad != NULL)
      job->u.HMAC._hashed_auth_key_xor_opad = (uint8_t *)buff;
    break;
  case IMB_AUTH_AES_XCBC:
    if (job->u.XCBC._k1_expanded != NULL)
      job->u.XCBC._k1_expanded = (uint32_t *)buff;
    if (job->u.XCBC._k2 != NULL)
      job->u.XCBC._k2 = (uint8_t *)buff;
    if (job->u.XCBC._k3 != NULL)
      job->u.XCBC._k3 = (uint8_t *)buff;
    break;
  case IMB_AUTH_AES_CCM:
    if (job->u.CCM.aad != NULL)
      job->u.CCM.aad = buff;
    if (job->u.CCM.aad_len_in_bytes > buffsize)
      job->u.CCM.aad_len_in_bytes = buffsize;
    break;
  case IMB_AUTH_AES_CMAC:
  case IMB_AUTH_AES_CMAC_BITLEN:
  case IMB_AUTH_AES_CMAC_256:
    if (job->u.CMAC._key_expanded != NULL)
      job->u.CMAC._key_expanded = buff;
    if (job->u.CMAC._skey1 != NULL)
      job->u.CMAC._skey1 = buff;
    if (job->u.CMAC._skey2 != NULL)
      job->u.CMAC._skey2 = buff;
    break;
  case IMB_AUTH_ZUC256_EIA3_BITLEN:
    if (job->u.ZUC_EIA3._iv23 != NULL)
      job->u.ZUC_EIA3._iv23 = (uint8_t *)buff;
    /* fall through */
  case IMB_AUTH_ZUC_EIA3_BITLEN:
    if (job->u.ZUC_EIA3._key != NULL)
      job->u.ZUC_EIA3._key = (uint8_t *)buff;
    if (job->u.ZUC_EIA3._iv != NULL)
      job->u.ZUC_EIA3._iv = (uint8_t *)buff;
    break;
  case IMB_AUTH_SNOW3G_UIA2_BITLEN:
    if (job->u.SNOW3G_UIA2._key != NULL)
      job->u.SNOW3G_UIA2._key = buff;
    if (job->u.SNOW3G_UIA2._iv != NULL)
      job->u.SNOW3G_UIA2._iv = buff;
    break;
  case IMB_AUTH_KASUMI_UIA1:
    if (job->u.KASUMI_UIA1._key != NULL)
      job->u.KASUMI_UIA1._key = buff;
    break;
  case IMB_AUTH_AES_GMAC:
  case IMB_AUTH_AES_GMAC_128:
  case IMB_AUTH_AES_GMAC_192:
  case IMB_AUTH_AES_GMAC_256:
    if (job->u.GMAC._key != NULL)
      job->u.GMAC._key = buff;
    if (job->u.GMAC._iv != NULL)
      job->u.GMAC._iv = buff;
    if (job->u.GMAC.iv_len_in_bytes > buffsize)
      job->u.GMAC.iv_len_in_bytes = buffsize;
    break;
  case IMB_AUTH_GHASH:
    if (job->u.GHASH._key != NULL)
      job->u.GHASH._key = buff;
    if (job->u.GHASH._init_tag != NULL)
      job->u.GHASH._init_tag = buff;
    break;
  case IMB_AUTH_POLY1305:
    if (job->u.POLY1305._key != NULL)
      job->u.POLY1305._key = buff;
    break;
  case IMB_AUTH_CHACHA20_POLY1305:
    if (job->u.CHACHA20_POLY1305.aad != NULL)
      job->u.CHACHA20_POLY1305.aad = buff;
    if (job->u.CHACHA20_POLY1305.aad_len_in_bytes > buffsize)
      job->u.CHACHA20_POLY1305.aad_len_in_bytes = buffsize;
    break;
  case IMB_AUTH_CHACHA20_POLY1305_SGL:
    if (job->u.CHACHA20_POLY1305.aad != NULL)
      job->u.CHACHA20_POLY1305.aad = buff;
    if (job->u.CHACHA20_POLY1305.ctx != NULL) {
      job->u.CHACHA20_POLY1305.ctx = buff;
      job->u.CHACHA20_POLY1305.ctx->remain_ks_bytes &= 63;
      job->u.CHACHA20_POLY1305.ctx->remain_ct_bytes &= 15;
    }
    if (job->u.CHACHA20_POLY1305.aad_len_in_bytes > buffsize)
      job->u.CHACHA20_POLY1305.aad_len_in_bytes = buffsize;
    break;
  case IMB_AUTH_SNOW_V_AEAD:
    if (job->u.SNOW_V_AEAD.aad != NULL)
      job->u.SNOW_V_AEAD.aad = buff;
    if (job->u.SNOW_V_AEAD.aad_len_in_bytes > buffsize)
      job->u.SNOW_V_AEAD.aad_len_in_bytes = buffsize;
    break;
  case IMB_AUTH_GCM_SGL:
    if (job->u.GCM.aad != NULL)
      job->u.GCM.aad = buff;
    if (job->u.GCM.ctx != NULL) {
      job->u.GCM.ctx = buff;
      job->u.GCM.ctx->partial_block_length &= 15;
    }
    if (job->u.GCM.aad_len_in_bytes > buffsize)
      job->u.GCM.aad_len_in_bytes = buffsize;
    if (job->iv_len_in_bytes > buffsize)
      job->iv_len_in_bytes = buffsize;
    break;
  default:
    break;
  }
}

/* function to read env variables to import specific hash mode */
static IMB_HASH_ALG hash_selection(void) {
  const char *a = getenv("HASH");

  if (a == NULL) {
    return 0;
  } else {
    if (strcmp(a, "IMB_AUTH_HMAC_SHA_1") == 0)
      return IMB_AUTH_HMAC_SHA_1;
    else if (strcmp(a, "IMB_AUTH_HMAC_SHA_224") == 0)
      return IMB_AUTH_HMAC_SHA_224;
    else if (strcmp(a, "IMB_AUTH_HMAC_SHA_256") == 0)
      return IMB_AUTH_HMAC_SHA_256;
    else if (strcmp(a, "IMB_AUTH_HMAC_SHA_384") == 0)
      return IMB_AUTH_HMAC_SHA_384;
    else if (strcmp(a, "IMB_AUTH_HMAC_SHA_512") == 0)
      return IMB_AUTH_HMAC_SHA_512;
    else if (strcmp(a, "IMB_AUTH_AES_XCBC") == 0)
      return IMB_AUTH_AES_XCBC;
    else if (strcmp(a, "IMB_AUTH_MD5") == 0)
      return IMB_AUTH_MD5;
    else if (strcmp(a, "IMB_AUTH_NULL") == 0)
      return IMB_AUTH_NULL;
    else if (strcmp(a, "IMB_AUTH_AES_GMAC") == 0)
      return IMB_AUTH_AES_GMAC;
    else if (strcmp(a, "IMB_AUTH_CUSTOM") == 0)
      return IMB_AUTH_CUSTOM;
    else if (strcmp(a, "IMB_AUTH_AES_CCM") == 0)
      return IMB_AUTH_AES_CCM;
    else if (strcmp(a, "IMB_AUTH_AES_CMAC") == 0)
      return IMB_AUTH_AES_CMAC;
    else if (strcmp(a, "IMB_AUTH_SHA_1") == 0)
      return IMB_AUTH_SHA_1;
    else if (strcmp(a, "IMB_AUTH_SHA_224") == 0)
      return IMB_AUTH_SHA_224;
    else if (strcmp(a, "IMB_AUTH_SHA_256") == 0)
      return IMB_AUTH_SHA_256;
    else if (strcmp(a, "IMB_AUTH_SHA_384") == 0)
      return IMB_AUTH_SHA_384;
    else if (strcmp(a, "IMB_AUTH_SHA_512") == 0)
      return IMB_AUTH_SHA_512;
    else if (strcmp(a, "IMB_AUTH_AES_CMAC_BITLEN") == 0)
      return IMB_AUTH_AES_CMAC_BITLEN;
    else if (strcmp(a, "IMB_AUTH_PON_CRC_BIP") == 0)
      return IMB_AUTH_PON_CRC_BIP;
    else if (strcmp(a, "IMB_AUTH_ZUC_EIA3_BITLEN") == 0)
      return IMB_AUTH_ZUC_EIA3_BITLEN;
    else if (strcmp(a, "IMB_AUTH_DOCSIS_CRC32") == 0)
      return IMB_AUTH_DOCSIS_CRC32;
    else if (strcmp(a, "IMB_AUTH_SNOW3G_UIA2_BITLEN") == 0)
      return IMB_AUTH_SNOW3G_UIA2_BITLEN;
    else if (strcmp(a, "IMB_AUTH_KASUMI_UIA1") == 0)
      return IMB_AUTH_KASUMI_UIA1;
    else if (strcmp(a, "IMB_AUTH_AES_GMAC_128") == 0)
      return IMB_AUTH_AES_GMAC_128;
    else if (strcmp(a, "IMB_AUTH_AES_GMAC_192") == 0)
      return IMB_AUTH_AES_GMAC_192;
    else if (strcmp(a, "IMB_AUTH_AES_GMAC_256") == 0)
      return IMB_AUTH_AES_GMAC_256;
    else if (strcmp(a, "IMB_AUTH_AES_CMAC_256") == 0)
      return IMB_AUTH_AES_CMAC_256;
    else if (strcmp(a, "IMB_AUTH_POLY1305") == 0)
      return IMB_AUTH_POLY1305;
    else if (strcmp(a, "IMB_AUTH_CHACHA20_POLY1305") == 0)
      return IMB_AUTH_CHACHA20_POLY1305;
    else if (strcmp(a, "IMB_AUTH_CHACHA20_POLY1305_SGL") == 0)
      return IMB_AUTH_CHACHA20_POLY1305_SGL;
    else if (strcmp(a, "IMB_AUTH_ZUC256_EIA3_BITLEN") == 0)
      return IMB_AUTH_ZUC256_EIA3_BITLEN;
    else if (strcmp(a, "IMB_AUTH_SNOW_V_AEAD") == 0)
      return IMB_AUTH_SNOW_V_AEAD;
    else if (strcmp(a, "IMB_AUTH_GCM_SGL") == 0)
      return IMB_AUTH_GCM_SGL;
    else if (strcmp(a, "IMB_AUTH_CRC32_ETHERNET_FCS") == 0)
      return IMB_AUTH_CRC32_ETHERNET_FCS;
    else if (strcmp(a, "IMB_AUTH_CRC32_SCTP") == 0)
      return IMB_AUTH_CRC32_SCTP;
    else if (strcmp(a, "IMB_AUTH_CRC32_WIMAX_OFDMA_DATA") == 0)
      return IMB_AUTH_CRC32_WIMAX_OFDMA_DATA;
    else if (strcmp(a, "IMB_AUTH_CRC24_LTE_A") == 0)
      return IMB_AUTH_CRC24_LTE_A;
    else if (strcmp(a, "IMB_AUTH_CRC24_LTE_B") == 0)
      return IMB_AUTH_CRC24_LTE_B;
    else if (strcmp(a, "IMB_AUTH_CRC16_X25") == 0)
      return IMB_AUTH_CRC16_X25;
    else if (strcmp(a, "IMB_AUTH_CRC16_FP_DATA") == 0)
      return IMB_AUTH_CRC16_FP_DATA;
    else if (strcmp(a, "IMB_AUTH_CRC11_FP_HEADER") == 0)
      return IMB_AUTH_CRC11_FP_HEADER;
    else if (strcmp(a, "IMB_AUTH_CRC10_IUUP_DATA") == 0)
      return IMB_AUTH_CRC10_IUUP_DATA;
    else if (strcmp(a, "IMB_AUTH_CRC8_WIMAX_OFDMA_HCS") == 0)
      return IMB_AUTH_CRC8_WIMAX_OFDMA_HCS;
    else if (strcmp(a, "IMB_AUTH_CRC7_FP_HEADER") == 0)
      return IMB_AUTH_CRC7_FP_HEADER;
    else if (strcmp(a, "IMB_AUTH_CRC6_IUUP_HEADER") == 0)
      return IMB_AUTH_CRC6_IUUP_HEADER;
    else if (strcmp(a, "IMB_AUTH_GHASH") == 0)
      return IMB_AUTH_GHASH;
    else
      return 0;
  }
}

/* function to read env variables to import specific cipher mode */
static IMB_CIPHER_MODE cipher_selection(void) {
  const char *a = getenv("CIPHER");

  if (a == NULL) {
    return 0;
  } else {
    if (strcmp(a, "IMB_CIPHER_CBC") == 0)
      return IMB_CIPHER_CBC;
    else if (strcmp(a, "IMB_CIPHER_CNTR") == 0)
      return IMB_CIPHER_CNTR;
    else if (strcmp(a, "IMB_CIPHER_NULL") == 0)
      return IMB_CIPHER_NULL;
    else if (strcmp(a, "IMB_CIPHER_DOCSIS_SEC_BPI") == 0)
      return IMB_CIPHER_DOCSIS_SEC_BPI;
    else if (strcmp(a, "IMB_CIPHER_GCM") == 0)
      return IMB_CIPHER_GCM;
    else if (strcmp(a, "IMB_CIPHER_CUSTOM") == 0)
      return IMB_CIPHER_CUSTOM;
    else if (strcmp(a, "IMB_CIPHER_DES") == 0)
      return IMB_CIPHER_DES;
    else if (strcmp(a, "IMB_CIPHER_DOCSIS_DES") == 0)
      return IMB_CIPHER_DOCSIS_DES;
    else if (strcmp(a, "IMB_CIPHER_CCM") == 0)
      return IMB_CIPHER_CCM;
    else if (strcmp(a, "IMB_CIPHER_DES3") == 0)
      return IMB_CIPHER_DES3;
    else if (strcmp(a, "IMB_CIPHER_PON_AES_CNTR") == 0)
      return IMB_CIPHER_PON_AES_CNTR;
    else if (strcmp(a, "IMB_CIPHER_ECB") == 0)
      return IMB_CIPHER_ECB;
    else if (strcmp(a, "IMB_CIPHER_CNTR_BITLEN") == 0)
      return IMB_CIPHER_CNTR_BITLEN;
    else if (strcmp(a, "IMB_CIPHER_ZUC_EEA3") == 0)
      return IMB_CIPHER_ZUC_EEA3;
    else if (strcmp(a, "IMB_CIPHER_SNOW3G_UEA2_BITLEN") == 0)
      return IMB_CIPHER_SNOW3G_UEA2_BITLEN;
    else if (strcmp(a, "IMB_CIPHER_KASUMI_UEA1_BITLEN") == 0)
      return IMB_CIPHER_KASUMI_UEA1_BITLEN;
    else if (strcmp(a, "IMB_CIPHER_CBCS_1_9") == 0)
      return IMB_CIPHER_CBCS_1_9;
    else if (strcmp(a, "IMB_CIPHER_CHACHA20") == 0)
      return IMB_CIPHER_CHACHA20;
    else if (strcmp(a, "IMB_CIPHER_CHACHA20_POLY1305") == 0)
      return IMB_CIPHER_CHACHA20_POLY1305;
    else if (strcmp(a, "IMB_CIPHER_CHACHA20_POLY1305_SGL") == 0)
      return IMB_CIPHER_CHACHA20_POLY1305_SGL;
    else if (strcmp(a, "IMB_CIPHER_SNOW_V") == 0)
      return IMB_CIPHER_SNOW_V;
    else if (strcmp(a, "IMB_CIPHER_SNOW_V_AEAD") == 0)
      return IMB_CIPHER_SNOW_V_AEAD;
    else if (strcmp(a, "IMB_CIPHER_GCM_SGL") == 0)
      return IMB_CIPHER_GCM_SGL;
    else
      return 0;
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t dataSize) {
  IMB_HASH_ALG hash;
  IMB_CIPHER_MODE cipher;
  IMB_CIPHER_DIRECTION dir;

  IMB_MGR *p_mgr = NULL;
  IMB_ARCH arch;
  unsigned i;
  const char *ar = getenv("ARCH");
  const char *api = getenv("API");
  const char *n_jobs = getenv("NUM_JOBS");
  const char *key_length = getenv("KEY_LEN");
  const char *cipher_dir = getenv("DIR");
  unsigned num_jobs;
  unsigned key_len;
  const size_t buffsize = BUFF_SIZE;
  bool single = false, cipher_burst = false, hash_burst = false, burst = false;

  if (n_jobs == NULL)
    num_jobs = 10;
  else
    num_jobs = strtoul(n_jobs, NULL, 10);
  if (key_length == NULL)
    key_len = 16;
  else
    key_len = strtoul(key_length, NULL, 10);

  /* Setting minimum datasize to always fill job structure  */
  if (dataSize < sizeof(IMB_JOB))
    return 0;

  if (num_jobs > MAX_BURST_JOBS || num_jobs == 0 || key_len == 0)
    return 0;

  if (cipher_dir != NULL) {
    if (strcmp(cipher_dir, "ENCRYPT") == 0)
      dir = IMB_DIR_ENCRYPT;
    else if (strcmp(cipher_dir, "DECRYPT") == 0)
      dir = IMB_DIR_DECRYPT;
    else {
      printf("Invalid cipher direction!\n");
      return EXIT_FAILURE;
    }
  } else {
    dir = IMB_DIR_ENCRYPT;
  }

  /* allocate multi-buffer manager */
  p_mgr = alloc_mb_mgr(0);
  if (p_mgr == NULL) {
    printf("Error allocating MB_MGR structure!\n");
    return EXIT_FAILURE;
  }
  if (ar == NULL) {
    init_mb_mgr_auto(p_mgr, &arch);
  } else {
    if (strcasecmp(ar, "AVX") == 0)
      init_mb_mgr_avx(p_mgr);
    else if (strcasecmp(ar, "AVX2") == 0)
      init_mb_mgr_avx2(p_mgr);
    else if (strcasecmp(ar, "AVX512") == 0)
      init_mb_mgr_avx512(p_mgr);
    else if (strcasecmp(ar, "SSE") == 0)
      init_mb_mgr_sse(p_mgr);
    else
      init_mb_mgr_auto(p_mgr, &arch);
  }

  IMB_JOB *job = NULL;
  /* create job array */

  if (api == NULL || (strcmp(api, "SINGLE") == 0)) {
    single = true;
  } else if (strcmp(api, "BURST") == 0) {
    burst = true;
  } else if (strcmp(api, "CIPHER_BURST") == 0) {
    cipher_burst = true;
  } else if (strcmp(api, "HASH_BURST") == 0) {
    hash_burst = true;
  } else {
    printf("Invalid API passed to application. Terminating\n");
    return 0;
  }

  if (single) {
    for (i = 0; i < num_jobs; i++) {
      hash = hash_selection();
      cipher = cipher_selection();
      job = IMB_GET_NEXT_JOB(p_mgr);
      memcpy(job, data, sizeof(*job));
      /*
       * setenv is invalid or unset -
       * receive flag and fuzz random
       * else a specific algo has been selected to fuzz.
       */
      if (hash == 0)
        job->hash_alg %= (IMB_AUTH_NUM + 1);
      else
        job->hash_alg = hash;
      if (cipher == 0)
        job->cipher_mode %= (IMB_CIPHER_NUM + 1);
      else
        job->cipher_mode = cipher;
      clamp_lengths(job, buffsize);
      static DECLARE_ALIGNED(uint8_t buff[2 * BUFF_SIZE], 64);
      static struct IMB_SGL_IOV sgl_segs[MAX_SGL_SEGS];

      fill_job_data(job, buff);
      fill_additional_cipher_data(job, sgl_segs, MAX_SGL_SEGS, buff, buffsize);
      fill_additional_hash_data(job, buff, buffsize);
      IMB_SUBMIT_JOB(p_mgr);
    }
  } else if (burst) {
    IMB_JOB *jobs[MAX_BURST_JOBS] = {NULL};

    while (IMB_GET_NEXT_BURST(p_mgr, num_jobs, jobs) < (uint32_t)num_jobs)
      IMB_FLUSH_BURST(p_mgr, num_jobs, jobs);

    for (i = 0; i < num_jobs; i++) {
      job = jobs[i];
      hash = hash_selection();
      cipher = cipher_selection();
      memcpy(job, data, sizeof(*job));
      /*
       * setenv is invalid or unset -
       * receive flag and fuzz random
       * else a specific algo has been
       * selected to fuzz.
       */
      if (hash == 0)
        job->hash_alg %= (IMB_AUTH_NUM + 1);
      else
        job->hash_alg = hash;
      if (cipher == 0)
        job->cipher_mode %= (IMB_CIPHER_NUM + 1);
      else
        job->cipher_mode = cipher;
      clamp_lengths(job, buffsize);
      static DECLARE_ALIGNED(uint8_t buff[2 * BUFF_SIZE], 64);
      static struct IMB_SGL_IOV sgl_segs[MAX_SGL_SEGS];

      fill_job_data(job, buff);
      fill_additional_cipher_data(job, sgl_segs, MAX_SGL_SEGS, buff, buffsize);
      fill_additional_hash_data(job, buff, buffsize);
    }

    IMB_SUBMIT_BURST(p_mgr, num_jobs, jobs);
  } else if (cipher_burst) {
    IMB_JOB jobs[MAX_BURST_JOBS] = {0};

    for (i = 0; i < num_jobs; i++) {
      job = &jobs[i];
      cipher = cipher_selection();
      memcpy(job, data, sizeof(*job));
      /*
       * setenv is invalid or unset -
       * receive flag and fuzz random
       * else a specific algo has been
       * selected to fuzz.
       */
      if (cipher == 0)
        cipher = (job->cipher_mode % (IMB_CIPHER_NUM + 1));

      job->cipher_mode = cipher;

      clamp_lengths(job, buffsize);
      static DECLARE_ALIGNED(uint8_t buff[2 * BUFF_SIZE], 64);
      static struct IMB_SGL_IOV sgl_segs[MAX_SGL_SEGS];

      fill_job_data(job, buff);
      fill_additional_cipher_data(job, sgl_segs, MAX_SGL_SEGS, buff, buffsize);
    }

    IMB_SUBMIT_CIPHER_BURST(p_mgr, jobs, num_jobs, cipher, dir, key_len);
  } else if (hash_burst) {
    IMB_JOB jobs[MAX_BURST_JOBS] = {0};

    for (i = 0; i < num_jobs; i++) {
      job = &jobs[i];
      hash = hash_selection();
      memcpy(job, data, sizeof(*job));
      /*
       * setenv is invalid or unset -
       * receive flag and fuzz random
       * else a specific algo has
       * been selected to fuzz.
       */
      if (hash == 0)
        hash = (job->hash_alg % (IMB_AUTH_NUM + 1));

      job->hash_alg = hash;

      clamp_lengths(job, buffsize);
      static DECLARE_ALIGNED(uint8_t buff[2 * BUFF_SIZE], 64);

      fill_job_data(job, buff);
      fill_additional_hash_data(job, buff, buffsize);
    }

    IMB_SUBMIT_HASH_BURST(p_mgr, jobs, num_jobs, hash);
  }

  free_mb_mgr(p_mgr);
  return 0;
}
