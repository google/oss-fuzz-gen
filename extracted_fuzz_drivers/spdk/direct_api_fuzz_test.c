/**********************************************************************
  Copyright(c) 2022-2023, Intel Corporation All rights reserved.

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

#include "utils.h"
#include <intel-ipsec-mb.h>
#include <malloc.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int LLVMFuzzerTestOneInput(const uint8_t *, size_t);
int LLVMFuzzerInitialize(int *, char ***);

IMB_ARCH arch = IMB_ARCH_NONE;
uint64_t flags = 0;

static void parse_matched(int argc, char **argv) {
  for (int i = 0; i < argc; i++) {
    if (strcasecmp(argv[i], "SSE") == 0)
      arch = IMB_ARCH_SSE;
    else if (strcasecmp(argv[i], "AVX") == 0)
      arch = IMB_ARCH_AVX;
    else if (strcasecmp(argv[i], "AVX2") == 0)
      arch = IMB_ARCH_AVX2;
    else if (strcasecmp(argv[i], "AVX512") == 0)
      arch = IMB_ARCH_AVX512;
    else if (strcasecmp(argv[i], "SHANI-OFF") == 0)
      flags |= IMB_FLAG_SHANI_OFF;
    else if (strcasecmp(argv[i], "GFNI-OFF") == 0)
      flags |= IMB_FLAG_GFNI_OFF;
  }
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  for (int i = 0; i < *argc; i++) {
    /*
     * Check if the current argument matches the
     * argument we are looking for.
     */
    if (strcasecmp((*argv)[i], "custom") == 0) {
      parse_matched(*argc - (i + 1), &((*argv)[i + 1]));
      /*
       *  Remove the matching argument and all arguments
       * after it from the command line.
       */
      *argc = i;

      break;
    }
  }
  return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static void fill_data(void *d, const size_t d_size, const void *s, const size_t s_size) {
  if (d == NULL || d_size == 0)
    return;

  memset(d, 0, d_size);

  if (s == NULL || s_size == 0)
    return;

  const size_t m_size = (s_size > d_size) ? d_size : s_size;
  memcpy(d, s, m_size);
}

/* ========================================================================== */
/* ========================================================================== */

static snow3g_key_schedule_t *snow3g_exp_key = NULL;
static uint8_t *snow3g_iv = NULL;
static uint32_t *snow3g_digest = NULL;

static void snow3g_end(void) {
  if (snow3g_digest != NULL)
    free(snow3g_digest);
  if (snow3g_exp_key != NULL)
    free(snow3g_exp_key);
  if (snow3g_iv != NULL)
    free(snow3g_iv);
  snow3g_exp_key = NULL;
  snow3g_iv = NULL;
  snow3g_digest = NULL;
}

static int snow3g_start(void) {
  snow3g_exp_key = (snow3g_key_schedule_t *)malloc(sizeof(snow3g_key_schedule_t));
  snow3g_iv = (uint8_t *)malloc(IMB_SNOW3G_IV_LEN_IN_BYTES);
  snow3g_digest = (uint32_t *)malloc(IMB_SNOW3G_DIGEST_LEN);
  if (snow3g_iv == NULL || snow3g_exp_key == NULL || snow3g_digest) {
    snow3g_end();
    return -1;
  }
  return 0;
}

static int test_snow3g_init_key_sched(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (dataSize < sizeof(snow3g_key_schedule_t))
    return -1;

  if (snow3g_start())
    return -1;

  IMB_SNOW3G_INIT_KEY_SCHED(p_mgr, buff, snow3g_exp_key);

  snow3g_end();
  return 0;
}

static int test_snow3g_f8_1_buff_bit(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (snow3g_start())
    return -1;

  const size_t dataSizeBits = dataSize * 8;
  const size_t offsetBits = buff[0] % dataSizeBits;
  const uint64_t lenBits = dataSizeBits - offsetBits;

  IMB_SNOW3G_F8_1_BUFFER_BIT(p_mgr, snow3g_exp_key, snow3g_iv, buff, buff, lenBits, offsetBits);
  snow3g_end();
  return 0;
}

static int test_snow3g_f8_1_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (snow3g_start())
    return -1;

  IMB_SNOW3G_F8_1_BUFFER(p_mgr, snow3g_exp_key, snow3g_iv, buff, buff, dataSize);
  snow3g_end();
  return 0;
}

static int test_snow3g_f8_2_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (snow3g_start())
    return -1;

  IMB_SNOW3G_F8_2_BUFFER(p_mgr, snow3g_exp_key, snow3g_iv, snow3g_iv, buff, buff, dataSize, buff, buff, dataSize);
  snow3g_end();
  return 0;
}

static int test_snow3g_f8_4_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (snow3g_start())
    return -1;

  IMB_SNOW3G_F8_4_BUFFER(p_mgr, snow3g_exp_key, snow3g_iv, snow3g_iv, snow3g_iv, snow3g_iv, buff, buff, dataSize, buff, buff, dataSize, buff, buff, dataSize, buff, buff, dataSize);
  snow3g_end();
  return 0;
}

static int test_snow3g_f8_8_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (snow3g_start())
    return -1;

  IMB_SNOW3G_F8_8_BUFFER(p_mgr, snow3g_exp_key, snow3g_iv, snow3g_iv, snow3g_iv, snow3g_iv, snow3g_iv, snow3g_iv, snow3g_iv, snow3g_iv, buff, buff, dataSize, buff, buff, dataSize, buff, buff, dataSize, buff, buff, dataSize, buff, buff, dataSize, buff, buff, dataSize, buff, buff, dataSize, buff, buff, dataSize);
  snow3g_end();
  return 0;
}

static int test_snow3g_f8_n_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (snow3g_start())
    return -1;

  const void *iv[8];
  const void *in[8];
  void *out[8];
  uint32_t len[8];

  for (int i = 0; i < 8; i++) {
    iv[i] = snow3g_iv;
    in[i] = buff;
    out[i] = buff;
    len[i] = dataSize;
  }

  IMB_SNOW3G_F8_N_BUFFER(p_mgr, snow3g_exp_key, iv, in, out, len, 8);
  snow3g_end();
  return 0;
}

struct test_snow3g_mb {
  size_t n;
  const void **iv;
  const void **in;
  void **out;
  uint32_t *len;
  const snow3g_key_schedule_t **key;
};

static void test_snow3g_mb_free(struct test_snow3g_mb *ts) {
  if (ts->key != NULL)
    free(ts->key);
  if (ts->iv != NULL)
    free(ts->iv);
  if (ts->out != NULL)
    free(ts->out);
  if (ts->in != NULL)
    free(ts->in);
  if (ts->len != NULL)
    free(ts->len);
  memset(ts, 0, sizeof(*ts));
}

static int test_snow3g_mb_alloc(struct test_snow3g_mb *ts, const size_t n) {
  ts->n = n;
  ts->key = malloc(n * sizeof(ts->key[0]));
  ts->iv = malloc(n * sizeof(ts->iv[0]));
  ts->in = malloc(n * sizeof(ts->in[0]));
  ts->out = malloc(n * sizeof(ts->out[0]));
  ts->len = malloc(n * sizeof(ts->len[0]));

  if (ts->key == NULL || ts->iv == NULL || ts->in == NULL || ts->out == NULL || ts->len == NULL) {
    test_snow3g_mb_free(ts);
    return -1;
  }

  return 0;
}

static void test_snow3g_mb_set1(struct test_snow3g_mb *ts, const snow3g_key_schedule_t *key, const void *iv, const void *in, void *out, const uint32_t len) {
  for (size_t i = 0; i < ts->n; i++) {
    ts->key[i] = key;
    ts->iv[i] = iv;
    ts->in[i] = in;
    ts->out[i] = out;
    ts->len[i] = len;
  }
}

static int test_snow3g_f8_8_multikey(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (snow3g_start())
    return -1;

  struct test_snow3g_mb ts;
  const uint32_t n = 8;

  if (test_snow3g_mb_alloc(&ts, n) != 0) {
    snow3g_end();
    return -1;
  }
  test_snow3g_mb_set1(&ts, snow3g_exp_key, snow3g_iv, buff, buff, (uint32_t)dataSize);
  IMB_SNOW3G_F8_8_BUFFER_MULTIKEY(p_mgr, ts.key, ts.iv, ts.in, ts.out, ts.len);
  test_snow3g_mb_free(&ts);
  snow3g_end();
  return 0;
}

static int test_snow3g_f8_iv_gen(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  (void)p_mgr;

  struct {
    uint32_t count;
    uint8_t bearer;
    uint8_t dir;
  } params;

  fill_data(&params, sizeof(params), buff, dataSize);

  void *iv = malloc(IMB_SNOW3G_IV_LEN_IN_BYTES);

  if (iv == NULL)
    return -1;
  snow3g_f8_iv_gen(params.count, params.bearer, params.dir, iv);
  free(iv);
  return 0;
}

static int test_snow3g_f8_n_multikey(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (snow3g_start())
    return -1;

  struct test_snow3g_mb ts;
  const uint32_t n = 9;

  if (test_snow3g_mb_alloc(&ts, n) != 0) {
    snow3g_end();
    return -1;
  }
  test_snow3g_mb_set1(&ts, snow3g_exp_key, snow3g_iv, buff, buff, (uint32_t)dataSize);
  IMB_SNOW3G_F8_N_BUFFER_MULTIKEY(p_mgr, ts.key, ts.iv, ts.in, ts.out, ts.len, n);
  test_snow3g_mb_free(&ts);
  snow3g_end();
  return 0;
}

static int test_snow3g_f9_1_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (snow3g_start())
    return -1;
  IMB_SNOW3G_F9_1_BUFFER(p_mgr, snow3g_exp_key, snow3g_iv, buff, dataSize, snow3g_digest);
  snow3g_end();
  return 0;
}

static int test_snow3g_f9_iv_gen(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  (void)p_mgr;

  struct {
    uint32_t count;
    uint32_t fresh;
    uint8_t dir;
  } params;

  fill_data(&params, sizeof(params), buff, dataSize);

  void *iv = malloc(IMB_SNOW3G_IV_LEN_IN_BYTES);

  if (iv == NULL)
    return -1;
  snow3g_f9_iv_gen(params.count, params.fresh, params.dir, iv);
  free(iv);
  return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static struct gcm_key_data *gcm_key = NULL;
static struct gcm_context_data *gcm_ctx = NULL;
static uint8_t *gcm_iv = NULL;
static uint8_t *gcm_aad = NULL;
static uint64_t gcm_aad_len;
static uint8_t *gcm_auth_tag = NULL;
static uint64_t gcm_tag_len;

static void gcm_end(void) {
  if (gcm_key != NULL)
    free(gcm_key);
  if (gcm_ctx != NULL)
    free(gcm_ctx);
  if (gcm_iv != NULL)
    free(gcm_iv);
  if (gcm_aad != NULL)
    free(gcm_aad);
  if (gcm_auth_tag != NULL)
    free(gcm_auth_tag);
  gcm_key = NULL;
  gcm_ctx = NULL;
  gcm_iv = NULL;
  gcm_aad = NULL;
  gcm_aad_len = 0;
  gcm_auth_tag = NULL;
  gcm_tag_len = 0;
}

static int gcm_start(const size_t dataSize, const uint8_t *data) {
  gcm_key = (struct gcm_key_data *)memalign(16, sizeof(struct gcm_key_data));
  gcm_ctx = (struct gcm_context_data *)memalign(16, sizeof(struct gcm_context_data));
  gcm_iv = (uint8_t *)malloc(IMB_GCM_IV_DATA_LEN);
  gcm_aad_len = dataSize;
  gcm_aad = (uint8_t *)malloc(gcm_aad_len);
  gcm_tag_len = dataSize;
  gcm_auth_tag = (uint8_t *)malloc(gcm_tag_len);
  if (gcm_key == NULL || gcm_ctx == NULL || gcm_iv == NULL || gcm_aad == NULL || gcm_auth_tag == NULL) {
    gcm_end();
    return -1;
  }
  fill_data(gcm_key, sizeof(struct gcm_key_data), data, dataSize);
  fill_data(gcm_ctx, sizeof(struct gcm_context_data), data, dataSize);
  fill_data(gcm_iv, IMB_GCM_IV_DATA_LEN, data, dataSize);
  fill_data(gcm_aad, gcm_aad_len, data, dataSize);
  fill_data(gcm_auth_tag, gcm_tag_len, data, dataSize);
  return 0;
}

static int test_aes_gcm_precomp(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (gcm_start(dataSize, buff) != 0)
    return -1;

  if (dataSize >= IMB_KEY_256_BYTES)
    IMB_AES256_GCM_PRECOMP(p_mgr, gcm_key);
  else if (dataSize >= IMB_KEY_192_BYTES)
    IMB_AES192_GCM_PRECOMP(p_mgr, gcm_key);
  else
    IMB_AES128_GCM_PRECOMP(p_mgr, gcm_key);

  gcm_end();
  return 0;
}

static int test_aes128_gcm_init_var_iv(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (gcm_start(dataSize, buff) != 0)
    return -1;

  IMB_AES128_GCM_INIT_VAR_IV(p_mgr, gcm_key, gcm_ctx, buff, dataSize, gcm_aad, gcm_aad_len);
  gcm_end();
  return 0;
}

static int test_aes192_gcm_init_var_iv(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (gcm_start(dataSize, buff) != 0)
    return -1;

  IMB_AES192_GCM_INIT_VAR_IV(p_mgr, gcm_key, gcm_ctx, buff, dataSize, gcm_aad, gcm_aad_len);
  gcm_end();
  return 0;
}

static int test_aes256_gcm_init_var_iv(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (gcm_start(dataSize, buff) != 0)
    return -1;

  IMB_AES256_GCM_INIT_VAR_IV(p_mgr, gcm_key, gcm_ctx, buff, dataSize, gcm_aad, gcm_aad_len);
  gcm_end();
  return 0;
}

static int test_aes_gcm_pre(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (dataSize < IMB_KEY_128_BYTES)
    return -1;

  if (gcm_start(dataSize, buff) != 0)
    return -1;

  if (dataSize >= IMB_KEY_256_BYTES)
    IMB_AES256_GCM_PRE(p_mgr, buff, gcm_key);
  else if (dataSize >= IMB_KEY_192_BYTES)
    IMB_AES192_GCM_PRE(p_mgr, buff, gcm_key);
  else
    IMB_AES128_GCM_PRE(p_mgr, buff, gcm_key);

  gcm_end();
  return 0;
}

static int test_aes128_gcm_enc(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (gcm_start(dataSize, buff) != 0)
    return -1;

  uint8_t *out = buff;
  const uint8_t *in = buff;
  const uint64_t len = dataSize;

  IMB_AES128_GCM_ENC(p_mgr, gcm_key, gcm_ctx, out, in, len, gcm_iv, gcm_aad, gcm_aad_len, gcm_auth_tag, gcm_tag_len);
  gcm_end();
  return 0;
}

static int test_aes128_gcm_dec(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (gcm_start(dataSize, buff) != 0)
    return -1;

  uint8_t *out = buff;
  const uint8_t *in = buff;
  const uint64_t len = dataSize;

  IMB_AES128_GCM_DEC(p_mgr, gcm_key, gcm_ctx, out, in, len, gcm_iv, gcm_aad, gcm_aad_len, gcm_auth_tag, gcm_tag_len);
  gcm_end();
  return 0;
}

static int test_aes192_gcm_enc(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (gcm_start(dataSize, buff) != 0)
    return -1;

  uint8_t *out = buff;
  const uint8_t *in = buff;
  const uint64_t len = dataSize;

  IMB_AES192_GCM_ENC(p_mgr, gcm_key, gcm_ctx, out, in, len, gcm_iv, gcm_aad, gcm_aad_len, gcm_auth_tag, gcm_tag_len);
  gcm_end();
  return 0;
}

static int test_aes192_gcm_dec(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (gcm_start(dataSize, buff) != 0)
    return -1;

  uint8_t *out = buff;
  const uint8_t *in = buff;
  const uint64_t len = dataSize;

  IMB_AES192_GCM_DEC(p_mgr, gcm_key, gcm_ctx, out, in, len, gcm_iv, gcm_aad, gcm_aad_len, gcm_auth_tag, gcm_tag_len);
  gcm_end();
  return 0;
}

static int test_aes256_gcm_enc(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (gcm_start(dataSize, buff) != 0)
    return -1;

  uint8_t *out = buff;
  const uint8_t *in = buff;
  const uint64_t len = dataSize;

  IMB_AES256_GCM_ENC(p_mgr, gcm_key, gcm_ctx, out, in, len, gcm_iv, gcm_aad, gcm_aad_len, gcm_auth_tag, gcm_tag_len);
  gcm_end();
  return 0;
}

static int test_aes256_gcm_dec(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (gcm_start(dataSize, buff) != 0)
    return -1;

  uint8_t *out = buff;
  const uint8_t *in = buff;
  const uint64_t len = dataSize;

  IMB_AES256_GCM_DEC(p_mgr, gcm_key, gcm_ctx, out, in, len, gcm_iv, gcm_aad, gcm_aad_len, gcm_auth_tag, gcm_tag_len);
  gcm_end();
  return 0;
}

static int test_aes128_gcm_enc_sgl(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (gcm_start(dataSize, buff) != 0)
    return -1;

  uint8_t *out = buff;
  const uint8_t *in = buff;
  const uint64_t len = dataSize;

  IMB_AES128_GCM_INIT(p_mgr, gcm_key, gcm_ctx, gcm_iv, gcm_aad, gcm_aad_len);
  IMB_AES128_GCM_ENC_UPDATE(p_mgr, gcm_key, gcm_ctx, out, in, len);
  IMB_AES128_GCM_ENC_FINALIZE(p_mgr, gcm_key, gcm_ctx, gcm_auth_tag, gcm_tag_len);
  gcm_end();
  return 0;
}

static int test_aes128_gcm_dec_sgl(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (gcm_start(dataSize, buff) != 0)
    return -1;

  uint8_t *out = buff;
  const uint8_t *in = buff;
  const uint64_t len = dataSize;

  IMB_AES128_GCM_INIT(p_mgr, gcm_key, gcm_ctx, gcm_iv, gcm_aad, gcm_aad_len);
  IMB_AES128_GCM_DEC_UPDATE(p_mgr, gcm_key, gcm_ctx, out, in, len);
  IMB_AES128_GCM_DEC_FINALIZE(p_mgr, gcm_key, gcm_ctx, gcm_auth_tag, gcm_tag_len);
  gcm_end();
  return 0;
}

static int test_aes192_gcm_enc_sgl(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (gcm_start(dataSize, buff) != 0)
    return -1;

  uint8_t *out = buff;
  const uint8_t *in = buff;
  uint64_t len = dataSize;

  IMB_AES192_GCM_INIT(p_mgr, gcm_key, gcm_ctx, gcm_iv, gcm_aad, gcm_aad_len);
  IMB_AES192_GCM_ENC_UPDATE(p_mgr, gcm_key, gcm_ctx, out, in, len);
  IMB_AES192_GCM_ENC_FINALIZE(p_mgr, gcm_key, gcm_ctx, gcm_auth_tag, gcm_tag_len);
  gcm_end();
  return 0;
}

static int test_aes192_gcm_dec_sgl(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (gcm_start(dataSize, buff) != 0)
    return -1;

  uint8_t *out = buff;
  const uint8_t *in = buff;
  const uint64_t len = dataSize;

  IMB_AES192_GCM_INIT(p_mgr, gcm_key, gcm_ctx, gcm_iv, gcm_aad, gcm_aad_len);
  IMB_AES192_GCM_DEC_UPDATE(p_mgr, gcm_key, gcm_ctx, out, in, len);
  IMB_AES192_GCM_DEC_FINALIZE(p_mgr, gcm_key, gcm_ctx, gcm_auth_tag, gcm_tag_len);
  gcm_end();
  return 0;
}

static int test_aes256_gcm_enc_sgl(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (gcm_start(dataSize, buff) != 0)
    return -1;

  uint8_t *out = buff;
  const uint8_t *in = buff;
  const uint64_t len = dataSize;

  IMB_AES256_GCM_INIT(p_mgr, gcm_key, gcm_ctx, gcm_iv, gcm_aad, gcm_aad_len);
  IMB_AES256_GCM_ENC_UPDATE(p_mgr, gcm_key, gcm_ctx, out, in, len);
  IMB_AES256_GCM_ENC_FINALIZE(p_mgr, gcm_key, gcm_ctx, gcm_auth_tag, gcm_tag_len);
  gcm_end();
  return 0;
}

static int test_aes256_gcm_dec_sgl(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (gcm_start(dataSize, buff) != 0)
    return -1;

  uint8_t *out = buff;
  const uint8_t *in = buff;
  const uint64_t len = dataSize;

  IMB_AES256_GCM_INIT(p_mgr, gcm_key, gcm_ctx, gcm_iv, gcm_aad, gcm_aad_len);
  IMB_AES256_GCM_DEC_UPDATE(p_mgr, gcm_key, gcm_ctx, out, in, len);
  IMB_AES256_GCM_DEC_FINALIZE(p_mgr, gcm_key, gcm_ctx, gcm_auth_tag, gcm_tag_len);
  gcm_end();
  return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static int test_aes128_gmac(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (gcm_start(dataSize, buff) != 0)
    return -1;

  /* use GCM AAD field as GMAC IV */
  IMB_AES128_GMAC_INIT(p_mgr, gcm_key, gcm_ctx, gcm_aad, gcm_aad_len);
  IMB_AES128_GMAC_UPDATE(p_mgr, gcm_key, gcm_ctx, buff, dataSize);
  IMB_AES128_GMAC_FINALIZE(p_mgr, gcm_key, gcm_ctx, gcm_auth_tag, gcm_tag_len);
  gcm_end();
  return 0;
}

static int test_aes192_gmac(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (gcm_start(dataSize, buff) != 0)
    return -1;

  /* use GCM AAD field as GMAC IV */
  IMB_AES192_GMAC_INIT(p_mgr, gcm_key, gcm_ctx, gcm_aad, gcm_aad_len);
  IMB_AES192_GMAC_UPDATE(p_mgr, gcm_key, gcm_ctx, buff, dataSize);
  IMB_AES192_GMAC_FINALIZE(p_mgr, gcm_key, gcm_ctx, gcm_auth_tag, gcm_tag_len);
  gcm_end();
  return 0;
}

static int test_aes256_gmac(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (gcm_start(dataSize, buff) != 0)
    return -1;

  /* use GCM AAD field as GMAC IV */
  IMB_AES256_GMAC_INIT(p_mgr, gcm_key, gcm_ctx, gcm_aad, gcm_aad_len);
  IMB_AES256_GMAC_UPDATE(p_mgr, gcm_key, gcm_ctx, buff, dataSize);
  IMB_AES256_GMAC_FINALIZE(p_mgr, gcm_key, gcm_ctx, gcm_auth_tag, gcm_tag_len);
  gcm_end();
  return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static int test_ghash_pre(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  /* GHASH key size */
  if (dataSize < 16)
    return -1;

  if (gcm_start(dataSize, buff) != 0)
    return -1;

  IMB_GHASH_PRE(p_mgr, buff, gcm_key);

  gcm_end();
  return 0;
}

static int test_ghash(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (gcm_start(dataSize, buff) != 0)
    return -1;

  IMB_GHASH(p_mgr, gcm_key, buff, dataSize, gcm_auth_tag, gcm_tag_len);

  gcm_end();
  return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static uint8_t *zuc_iv = NULL;
static uint8_t *zuc_key = NULL;
static uint32_t *zuc_tag = NULL;

static void zuc_end(void) {
  if (zuc_key != NULL)
    free(zuc_key);
  if (zuc_iv != NULL)
    free(zuc_iv);
  if (zuc_tag != NULL)
    free(zuc_tag);
  zuc_key = NULL;
  zuc_iv = NULL;
  zuc_tag = NULL;
}

static int zuc_start(const size_t dataSize, const uint8_t *data) {
  zuc_key = (uint8_t *)malloc(IMB_ZUC_KEY_LEN_IN_BYTES);
  zuc_iv = (uint8_t *)malloc(IMB_ZUC_IV_LEN_IN_BYTES);
  zuc_tag = (uint32_t *)malloc(IMB_ZUC_DIGEST_LEN_IN_BYTES);

  if (zuc_key == NULL || zuc_iv == NULL || zuc_tag == NULL) {
    zuc_end();
    return -1;
  }
  fill_data(zuc_key, IMB_ZUC_KEY_LEN_IN_BYTES, data, dataSize);
  fill_data(zuc_iv, IMB_ZUC_IV_LEN_IN_BYTES, data, dataSize);
  fill_data(zuc_tag, IMB_ZUC_DIGEST_LEN_IN_BYTES, data, dataSize);
  return 0;
}

static int test_zuc_eea3_1_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (zuc_start(dataSize, buff) != 0)
    return -1;

  IMB_ZUC_EEA3_1_BUFFER(p_mgr, zuc_key, zuc_iv, buff, buff, dataSize);
  zuc_end();
  return 0;
}

static int test_zuc_eea3_iv_gen(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  (void)p_mgr;

  struct {
    uint32_t count;
    uint8_t bearer;
    uint8_t dir;
  } params;

  fill_data(&params, sizeof(params), buff, dataSize);

  void *iv = malloc(IMB_ZUC_IV_LEN_IN_BYTES);

  if (iv == NULL)
    return -1;
  zuc_eea3_iv_gen(params.count, params.bearer, params.dir, iv);
  free(iv);
  return 0;
}

struct test_zuc_mb {
  size_t n;
  const void **key;
  const void **iv;
  const void **in;
  void **out; /* eea3 specific */
  uint32_t *len;
  uint32_t **tag; /* eia3 specific */
};

static void test_zuc_mb_free(struct test_zuc_mb *ts) {
  if (ts->key != NULL)
    free(ts->key);
  if (ts->iv != NULL)
    free(ts->iv);
  if (ts->out != NULL)
    free(ts->out);
  if (ts->in != NULL)
    free(ts->in);
  if (ts->len != NULL)
    free(ts->len);
  if (ts->tag != NULL)
    free(ts->tag);
  memset(ts, 0, sizeof(*ts));
}

static int test_zuc_mb_alloc(struct test_zuc_mb *ts, const size_t n) {
  ts->n = n;

  ts->key = malloc(n * sizeof(ts->key[0]));
  ts->iv = malloc(n * sizeof(ts->iv[0]));
  ts->in = malloc(n * sizeof(ts->in[0]));
  ts->out = malloc(n * sizeof(ts->out[0]));
  ts->len = malloc(n * sizeof(ts->len[0]));

  ts->tag = malloc(n * sizeof(ts->tag[0]));

  if (ts->key == NULL || ts->iv == NULL || ts->in == NULL || ts->out == NULL || ts->len == NULL || ts->tag == NULL) {
    test_zuc_mb_free(ts);
    return -1;
  }

  return 0;
}

static void test_zuc_mb_set1(struct test_zuc_mb *ts, const void *key, const void *iv, const void *in, void *out, const uint32_t len, uint32_t *tag) {
  for (size_t i = 0; i < ts->n; i++) {
    ts->key[i] = key;
    ts->iv[i] = iv;
    ts->in[i] = in;
    ts->out[i] = out;
    ts->len[i] = len;
    ts->tag[i] = tag;
  }
}

static int test_zuc_eea3_4_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (zuc_start(dataSize, buff) != 0)
    return -1;

  struct test_zuc_mb ts;
  const uint32_t n = 4;

  if (test_zuc_mb_alloc(&ts, n) != 0) {
    zuc_end();
    return -1;
  }
  test_zuc_mb_set1(&ts, zuc_key, zuc_iv, buff, buff, dataSize, NULL);
  IMB_ZUC_EEA3_4_BUFFER(p_mgr, ts.key, ts.iv, ts.in, ts.out, ts.len);
  test_zuc_mb_free(&ts);
  zuc_end();
  return 0;
}

static int test_zuc_eea3_n_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (zuc_start(dataSize, buff) != 0)
    return -1;

  struct test_zuc_mb ts;
  const uint32_t n = 8;

  if (test_zuc_mb_alloc(&ts, n) != 0) {
    zuc_end();
    return -1;
  }
  test_zuc_mb_set1(&ts, zuc_key, zuc_iv, buff, buff, dataSize, NULL);
  IMB_ZUC_EEA3_N_BUFFER(p_mgr, ts.key, ts.iv, ts.in, ts.out, ts.len, n);
  test_zuc_mb_free(&ts);
  zuc_end();
  return 0;
}

static int test_zuc_eia3_1_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (zuc_start(dataSize, buff) != 0)
    return -1;

  const uint32_t len = dataSize * 8;

  IMB_ZUC_EIA3_1_BUFFER(p_mgr, zuc_key, zuc_iv, buff, len, zuc_tag);
  zuc_end();
  return 0;
}

static int test_zuc_eia3_n_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (dataSize < IMB_ZUC_KEY_LEN_IN_BYTES)
    return -1;

  struct test_zuc_mb ts;
  const uint32_t n = 9;

  if (test_zuc_mb_alloc(&ts, n) != 0) {
    zuc_end();
    return -1;
  }
  test_zuc_mb_set1(&ts, zuc_key, zuc_iv, buff, NULL, dataSize * 8, zuc_tag);
  IMB_ZUC_EIA3_N_BUFFER(p_mgr, ts.key, ts.iv, ts.in, ts.len, ts.tag, n);
  test_zuc_mb_free(&ts);
  zuc_end();
  return 0;
}

static int test_zuc_eia3_iv_gen(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  (void)p_mgr;

  struct {
    uint32_t count;
    uint8_t bearer;
    uint8_t dir;
  } params;

  fill_data(&params, sizeof(params), buff, dataSize);

  void *iv = malloc(IMB_ZUC_IV_LEN_IN_BYTES);

  if (iv == NULL)
    return -1;
  zuc_eia3_iv_gen(params.count, params.bearer, params.dir, iv);
  free(iv);
  return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static uint8_t *ccp_key = NULL;
static struct chacha20_poly1305_context_data *ccp_ctx = NULL;
static uint8_t *ccp_iv = NULL;
static uint8_t *ccp_aad = NULL;
static uint64_t ccp_aad_len;
static uint8_t *ccp_auth_tag = NULL;
static uint64_t ccp_tag_len;

static void ccp_end(void) {
  if (ccp_key != NULL)
    free(ccp_key);
  if (ccp_ctx != NULL)
    free(ccp_ctx);
  if (ccp_iv != NULL)
    free(ccp_iv);
  if (ccp_aad != NULL)
    free(ccp_aad);
  if (ccp_auth_tag != NULL)
    free(ccp_auth_tag);
  ccp_key = NULL;
  ccp_ctx = NULL;
  ccp_iv = NULL;
  ccp_aad = NULL;
  ccp_aad_len = 0;
  ccp_auth_tag = NULL;
  ccp_tag_len = 0;
}

static int ccp_start(const size_t dataSize, const uint8_t *data) {
  ccp_key = (uint8_t *)malloc(IMB_CHACHA20_POLY1305_KEY_SIZE);
  ccp_ctx = (struct chacha20_poly1305_context_data *)memalign(16, sizeof(struct chacha20_poly1305_context_data));
  ccp_iv = (uint8_t *)malloc(IMB_CHACHA20_POLY1305_IV_SIZE);
  ccp_aad_len = dataSize;
  ccp_aad = (uint8_t *)malloc(ccp_aad_len);
  ccp_tag_len = dataSize;
  ccp_auth_tag = (uint8_t *)malloc(ccp_tag_len);
  if (ccp_key == NULL || ccp_ctx == NULL || ccp_iv == NULL || ccp_aad == NULL || ccp_auth_tag == NULL) {
    ccp_end();
    return -1;
  }
  fill_data(ccp_key, IMB_CHACHA20_POLY1305_KEY_SIZE, data, dataSize);
  fill_data(ccp_ctx, sizeof(struct chacha20_poly1305_context_data), data, dataSize);
  fill_data(ccp_iv, IMB_CHACHA20_POLY1305_IV_SIZE, data, dataSize);
  fill_data(ccp_aad, ccp_aad_len, data, dataSize);
  fill_data(ccp_auth_tag, ccp_tag_len, data, dataSize);
  return 0;
}

static int test_chacha_poly_enc(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (ccp_start(dataSize, buff) != 0)
    return -1;

  uint8_t *out = buff;
  const uint8_t *in = buff;
  const uint64_t len = dataSize;

  IMB_CHACHA20_POLY1305_INIT(p_mgr, ccp_key, ccp_ctx, ccp_iv, ccp_aad, ccp_aad_len);
  IMB_CHACHA20_POLY1305_ENC_UPDATE(p_mgr, ccp_key, ccp_ctx, out, in, len);
  IMB_CHACHA20_POLY1305_ENC_FINALIZE(p_mgr, ccp_ctx, ccp_auth_tag, ccp_tag_len);

  ccp_end();
  return 0;
}

static int test_chacha_poly_dec(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (ccp_start(dataSize, buff) != 0)
    return -1;

  uint8_t *out = buff;
  const uint8_t *in = buff;
  const uint64_t len = dataSize;

  IMB_CHACHA20_POLY1305_INIT(p_mgr, ccp_key, ccp_ctx, ccp_iv, ccp_aad, ccp_aad_len);
  IMB_CHACHA20_POLY1305_DEC_UPDATE(p_mgr, ccp_key, ccp_ctx, out, in, len);
  IMB_CHACHA20_POLY1305_DEC_FINALIZE(p_mgr, ccp_ctx, ccp_auth_tag, ccp_tag_len);

  ccp_end();
  return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static int test_crc32_ethernet_fcs(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  IMB_CRC32_ETHERNET_FCS(p_mgr, buff, dataSize);
  return 0;
}

static int test_crc16_x25(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  IMB_CRC16_X25(p_mgr, buff, dataSize);
  return 0;
}

static int test_crc32_sctp(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  IMB_CRC32_SCTP(p_mgr, buff, dataSize);
  return 0;
}

static int test_crc24_lte_a(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  IMB_CRC24_LTE_A(p_mgr, buff, dataSize);
  return 0;
}

static int test_crc24_lte_b(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  IMB_CRC24_LTE_B(p_mgr, buff, dataSize);
  return 0;
}

static int test_crc16_fp_data(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  IMB_CRC16_FP_DATA(p_mgr, buff, dataSize);
  return 0;
}

static int test_crc11_fp_header(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  IMB_CRC11_FP_HEADER(p_mgr, buff, dataSize);
  return 0;
}

static int test_crc7_fp_header(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  IMB_CRC7_FP_HEADER(p_mgr, buff, dataSize);
  return 0;
}

static int test_crc10_iuup_data(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  IMB_CRC10_IUUP_DATA(p_mgr, buff, dataSize);
  return 0;
}

static int test_crc6_iuup_header(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  IMB_CRC6_IUUP_HEADER(p_mgr, buff, dataSize);
  return 0;
}

static int test_crc32_wimax_ofdma_data(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  IMB_CRC32_WIMAX_OFDMA_DATA(p_mgr, buff, dataSize);
  return 0;
}

static int test_crc8_wimax_ofdma_hcs(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  IMB_CRC8_WIMAX_OFDMA_HCS(p_mgr, buff, dataSize);
  return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static uint64_t *kasumi_iv = NULL;
static kasumi_key_sched_t *kasumi_key = NULL;
static uint32_t *kasumi_tag = NULL;

static void kasumi_end(void) {
  if (kasumi_key != NULL)
    free(kasumi_key);
  if (kasumi_iv != NULL)
    free(kasumi_iv);
  if (kasumi_tag != NULL)
    free(kasumi_tag);
  kasumi_key = NULL;
  kasumi_iv = NULL;
  kasumi_tag = NULL;
}

static int kasumi_start(const size_t dataSize, const uint8_t *data) {
  kasumi_key = (kasumi_key_sched_t *)malloc(sizeof(kasumi_key_sched_t));
  kasumi_iv = (uint64_t *)malloc(IMB_KASUMI_IV_SIZE);
  kasumi_tag = (uint32_t *)malloc(IMB_KASUMI_DIGEST_SIZE);

  if (kasumi_key == NULL || kasumi_iv == NULL || kasumi_tag == NULL) {
    kasumi_end();
    return -1;
  }
  fill_data(kasumi_key, sizeof(kasumi_key_sched_t), data, dataSize);
  fill_data(kasumi_iv, IMB_KASUMI_IV_SIZE, data, dataSize);
  fill_data(kasumi_tag, IMB_KASUMI_DIGEST_SIZE, data, dataSize);
  return 0;
}

static int test_kasumi_f8_init_key_sched(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (dataSize < IMB_KASUMI_KEY_SIZE)
    return -1;

  if (kasumi_start(dataSize, buff) != 0)
    return -1;

  IMB_KASUMI_INIT_F8_KEY_SCHED(p_mgr, buff, kasumi_key);
  kasumi_end();
  return 0;
}

static int test_kasumi_f8_iv_gen(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  (void)p_mgr;

  struct {
    uint32_t count;
    uint8_t bearer;
    uint8_t dir;
  } params;

  fill_data(&params, sizeof(params), buff, dataSize);

  void *iv = malloc(IMB_KASUMI_IV_SIZE);

  if (iv == NULL)
    return -1;
  kasumi_f8_iv_gen(params.count, params.bearer, params.dir, iv);
  free(iv);
  return 0;
}

static int test_kasumi_f8_1_buff_bit(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (kasumi_start(dataSize, buff) != 0)
    return -1;

  const uint32_t offset = (dataSize > 0) ? (buff[0] % (dataSize * 8)) : 0;
  uint8_t *out = buff;
  const uint8_t *in = buff;
  const uint64_t len = (dataSize * 8) - offset;

  IMB_KASUMI_F8_1_BUFFER_BIT(p_mgr, kasumi_key, kasumi_iv[0], in, out, len, offset);
  kasumi_end();
  return 0;
}

static int test_kasumi_f8_1_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (kasumi_start(dataSize, buff) != 0)
    return -1;

  uint8_t *out = buff;
  const uint8_t *in = buff;
  const uint64_t len = dataSize;

  IMB_KASUMI_F8_1_BUFFER(p_mgr, kasumi_key, kasumi_iv[0], in, out, len);
  kasumi_end();
  return 0;
}

static int test_kasumi_f8_2_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (kasumi_start(dataSize, buff) != 0)
    return -1;

  uint8_t *out = buff;
  const uint8_t *in = buff;
  const uint64_t len = dataSize;

  IMB_KASUMI_F8_2_BUFFER(p_mgr, kasumi_key, kasumi_iv[0], kasumi_iv[0], in, out, len, in, out, len);
  kasumi_end();
  return 0;
}

static int test_kasumi_f8_3_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (kasumi_start(dataSize, buff) != 0)
    return -1;

  uint8_t *out = buff;
  const uint8_t *in = buff;
  const uint64_t len = dataSize;

  IMB_KASUMI_F8_3_BUFFER(p_mgr, kasumi_key, kasumi_iv[0], kasumi_iv[0], kasumi_iv[0], in, out, in, out, in, out, len);
  kasumi_end();
  return 0;
}

static int test_kasumi_f8_4_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (kasumi_start(dataSize, buff) != 0)
    return -1;

  uint8_t *out = buff;
  const uint8_t *in = buff;
  const uint64_t len = dataSize;

  IMB_KASUMI_F8_4_BUFFER(p_mgr, kasumi_key, kasumi_iv[0], kasumi_iv[0], kasumi_iv[0], kasumi_iv[0], in, out, in, out, in, out, in, out, len);
  kasumi_end();
  return 0;
}

static int test_kasumi_f8_n_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  uint64_t *iv = malloc(8 * IMB_KASUMI_IV_SIZE);

  if (iv == NULL)
    return -1;

  if (kasumi_start(dataSize, buff) != 0) {
    free(iv);
    return -1;
  }

  const void *in[8];
  void *out[8];
  uint32_t len[8];

  for (int i = 0; i < 8; i++) {
    in[i] = buff;
    out[i] = buff;
    len[i] = dataSize;
  }

  IMB_KASUMI_F8_N_BUFFER(p_mgr, kasumi_key, iv, in, out, len, 8);
  kasumi_end();
  free(iv);
  return 0;
}

static int test_kasumi_f9_1_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (kasumi_start(dataSize, buff) != 0)
    return -1;

  const uint8_t *in = buff;
  const uint64_t len = dataSize;

  IMB_KASUMI_F9_1_BUFFER(p_mgr, kasumi_key, in, len, kasumi_tag);
  kasumi_end();
  return 0;
}

static int test_kasumi_f9_1_buff_user(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (kasumi_start(dataSize, buff) != 0)
    return -1;

  const uint8_t *in = buff;
  const uint64_t len = dataSize * 8;

  const uint64_t iv = (dataSize > 0) ? (uint64_t)buff[0] : 0;
  const uint32_t dir = (dataSize > 0) ? (uint32_t)buff[0] * 8 : 0;

  IMB_KASUMI_F9_1_BUFFER_USER(p_mgr, kasumi_key, iv, in, len, kasumi_tag, dir);
  kasumi_end();
  return 0;
}

static int test_kasumi_f9_init_key_sched(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (dataSize < IMB_KASUMI_KEY_SIZE)
    return -1;

  if (kasumi_start(dataSize, buff) != 0)
    return -1;

  IMB_KASUMI_INIT_F9_KEY_SCHED(p_mgr, buff, kasumi_key);
  kasumi_end();
  return 0;
}

static int test_kasumi_f9_iv_gen(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  (void)p_mgr;

  struct {
    uint32_t count;
    uint32_t fresh;
  } params;

  fill_data(&params, sizeof(params), buff, dataSize);

  void *iv = malloc(IMB_KASUMI_IV_SIZE);

  if (iv == NULL)
    return -1;
  kasumi_f9_iv_gen(params.count, params.fresh, iv);
  free(iv);
  return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static int test_imb_clear_mem(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  (void)p_mgr;

  imb_clear_mem(buff, dataSize);
  return 0;
}

/* ========================================================================== */
/* ========================================================================== */

struct test_quic_mb {
  size_t n;
  const void **array_src;
  void **array_dst;
  const void **array_aad;
  void **array_tag;
  const void **array_iv;
  uint64_t *array_len;
};

static void test_quic_mb_free(struct test_quic_mb *ts) {
  if (ts->array_tag != NULL)
    free(ts->array_tag);
  if (ts->array_src != NULL)
    free(ts->array_src);
  if (ts->array_dst != NULL)
    free(ts->array_dst);
  if (ts->array_aad != NULL)
    free(ts->array_aad);
  if (ts->array_iv != NULL)
    free(ts->array_iv);
  if (ts->array_len != NULL)
    free(ts->array_len);
  memset(ts, 0, sizeof(*ts));
}

static int test_quic_mb_alloc(struct test_quic_mb *ts, const size_t n) {
  ts->n = n;
  ts->array_tag = malloc(n * sizeof(ts->array_tag[0]));
  ts->array_src = malloc(n * sizeof(ts->array_src[0]));
  ts->array_dst = malloc(n * sizeof(ts->array_dst[0]));
  ts->array_iv = malloc(n * sizeof(ts->array_iv[0]));
  ts->array_len = malloc(n * sizeof(ts->array_len[0]));
  ts->array_aad = malloc(n * sizeof(ts->array_aad[0]));

  if (ts->array_tag == NULL || ts->array_src == NULL || ts->array_dst == NULL || ts->array_aad == NULL || ts->array_len == NULL || ts->array_iv == NULL) {
    test_quic_mb_free(ts);
    return -1;
  }
  return 0;
}

static void test_quic_mb_set1(struct test_quic_mb *ts, const void *aad, const void *src, void *dst, void *tag, const void *iv, const uint64_t len) {
  for (size_t i = 0; i < ts->n; i++) {
    ts->array_tag[i] = tag;
    ts->array_src[i] = src;
    ts->array_dst[i] = dst;
    ts->array_len[i] = len;
    ts->array_aad[i] = aad;
    ts->array_iv[i] = iv;
  }
}

static int test_imb_quic_aes_gcm(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (gcm_start(dataSize, buff) != 0)
    return -1;

  const uint64_t n = (dataSize > 0) ? (uint64_t)buff[0] : 4;
  struct test_quic_mb ts;

  if (test_quic_mb_alloc(&ts, n) != 0) {
    gcm_end();
    return -1;
  }

  const IMB_CIPHER_DIRECTION cipher_dir = (dataSize > 0) ? (IMB_CIPHER_DIRECTION)(buff[0] >> 6) : 0;
  const IMB_KEY_SIZE_BYTES key_size = (dataSize > 0) ? (IMB_KEY_SIZE_BYTES)(buff[0] & 0x38) : IMB_KEY_128_BYTES;

  test_quic_mb_set1(&ts, gcm_aad, buff, buff, gcm_auth_tag, gcm_iv, dataSize);

  imb_quic_aes_gcm(p_mgr, gcm_key, key_size, cipher_dir, ts.array_dst, ts.array_src, ts.array_len, ts.array_iv, ts.array_aad, gcm_aad_len, ts.array_tag, gcm_tag_len, n);
  test_quic_mb_free(&ts);
  gcm_end();
  return 0;
}

static int test_imb_quic_chacha20_poly1305(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (ccp_start(dataSize, buff) != 0)
    return -1;

  const uint64_t n = (dataSize > 0) ? (uint64_t)buff[0] : 4;
  struct test_quic_mb ts;

  if (test_quic_mb_alloc(&ts, n) != 0) {
    ccp_end();
    return -1;
  }

  const IMB_CIPHER_DIRECTION cipher_dir = (dataSize > 0) ? (IMB_CIPHER_DIRECTION)(buff[0] >> 6) : 0;

  test_quic_mb_set1(&ts, ccp_aad, buff, buff, ccp_auth_tag, ccp_iv, dataSize);

  imb_quic_chacha20_poly1305(p_mgr, ccp_key, cipher_dir, ts.array_dst, ts.array_src, ts.array_len, ts.array_iv, ts.array_aad, ccp_aad_len, ts.array_tag, n);
  test_quic_mb_free(&ts);
  ccp_end();
  return 0;
}

static int test_imb_quic_hp_aes_ecb(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  const IMB_KEY_SIZE_BYTES key_size = (dataSize > 0) ? (IMB_KEY_SIZE_BYTES)(buff[0] & 0x38) : IMB_KEY_128_BYTES;

  void *dst = malloc(5);

  if (dst == NULL)
    return -1;
  fill_data(dst, 5, buff, dataSize);

  void *src = malloc(16);

  if (src == NULL) {
    free(dst);
    return -1;
  }
  fill_data(src, 16, buff, dataSize);

  size_t expkey_size;

  if (key_size >= IMB_KEY_256_BYTES)
    expkey_size = 15 * 16;
  else if (key_size >= IMB_KEY_192_BYTES)
    expkey_size = 13 * 16;
  else
    expkey_size = 11 * 16;

  void *expkey = malloc(expkey_size);

  if (expkey == NULL) {
    free(dst);
    free(src);
    return -1;
  }
  fill_data(expkey, expkey_size, buff, dataSize);

  const uint64_t n = (dataSize > 0) ? (uint64_t)buff[0] : 4;
  struct test_quic_mb ts;

  if (test_quic_mb_alloc(&ts, n) != 0) {
    free(dst);
    free(src);
    free(expkey);
    return -1;
  }

  test_quic_mb_set1(&ts, NULL, src, dst, NULL, NULL, 0);

  imb_quic_hp_aes_ecb(p_mgr, expkey, ts.array_dst, ts.array_src, n, key_size);

  test_quic_mb_free(&ts);
  free(dst);
  free(src);
  free(expkey);
  return 0;
}

static int test_imb_quic_hp_chacha20(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  void *dst = malloc(5);

  if (dst == NULL)
    return -1;
  fill_data(dst, 5, buff, dataSize);

  void *src = malloc(16);

  if (src == NULL) {
    free(dst);
    return -1;
  }
  fill_data(src, 16, buff, dataSize);

  const size_t key_size = IMB_KEY_256_BYTES;
  void *key = malloc(key_size);

  if (key == NULL) {
    free(dst);
    free(src);
    return -1;
  }
  fill_data(key, key_size, buff, dataSize);

  const uint64_t n = (dataSize > 0) ? (uint64_t)buff[0] : 4;
  struct test_quic_mb ts;

  if (test_quic_mb_alloc(&ts, n) != 0) {
    free(dst);
    free(src);
    free(key);
    return -1;
  }

  test_quic_mb_set1(&ts, NULL, src, dst, NULL, NULL, 0);

  imb_quic_hp_chacha20(p_mgr, key, ts.array_dst, ts.array_src, n);

  test_quic_mb_free(&ts);
  free(dst);
  free(src);
  free(key);
  return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static void test_aes_exp_free(void **ekey, void **dkey) {
  void *e = *ekey;
  void *d = *dkey;

  if (e != NULL)
    free(e);
  if (d != NULL)
    free(d);
  *ekey = NULL;
  *dkey = NULL;
}

static int test_aes_exp_alloc(const unsigned rounds, void **ekey, void **dkey) {
  void *e = malloc(rounds * 16);
  void *d = malloc(rounds * 16);

  *ekey = e;
  *dkey = d;

  if (e == NULL || d == NULL) {
    test_aes_exp_free(ekey, dkey);
    return -1;
  }

  return 0;
}

static int test_imb_aes_keyexp_128(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (dataSize < IMB_KEY_128_BYTES)
    return -1;

  void *ekey, *dkey;

  if (test_aes_exp_alloc(11, &ekey, &dkey) != 0)
    return -1;

  IMB_AES_KEYEXP_128(p_mgr, buff, ekey, dkey);
  test_aes_exp_free(&ekey, &dkey);
  return 0;
}

static int test_imb_aes_keyexp_192(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (dataSize < IMB_KEY_192_BYTES)
    return -1;

  void *ekey, *dkey;

  if (test_aes_exp_alloc(13, &ekey, &dkey) != 0)
    return -1;

  IMB_AES_KEYEXP_192(p_mgr, buff, ekey, dkey);
  test_aes_exp_free(&ekey, &dkey);
  return 0;
}

static int test_imb_aes_keyexp_256(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  if (dataSize < IMB_KEY_256_BYTES)
    return -1;

  void *ekey, *dkey;

  if (test_aes_exp_alloc(15, &ekey, &dkey) != 0)
    return -1;

  IMB_AES_KEYEXP_256(p_mgr, buff, ekey, dkey);
  test_aes_exp_free(&ekey, &dkey);
  return 0;
}

static int test_imb_aes_subkey_cmac128(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  void *skey1, *skey2, *ekey, *dkey;

  if (test_aes_exp_alloc(1, &skey1, &skey2) != 0)
    return -1;

  if (test_aes_exp_alloc(11, &ekey, &dkey) != 0) {
    test_aes_exp_free(&skey1, &skey2);
    return -1;
  }

  const size_t sz_ekey = 11 * 16;

  memset(ekey, 0, sz_ekey);
  memcpy(ekey, buff, (dataSize > sz_ekey) ? sz_ekey : dataSize);

  IMB_AES_CMAC_SUBKEY_GEN_128(p_mgr, ekey, skey1, skey2);

  test_aes_exp_free(&skey1, &skey2);
  test_aes_exp_free(&ekey, &dkey);
  return 0;
}

static int test_imb_aes_subkey_cmac256(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  void *skey1, *skey2, *ekey, *dkey;

  if (test_aes_exp_alloc(1, &skey1, &skey2) != 0)
    return -1;

  if (test_aes_exp_alloc(15, &ekey, &dkey) != 0) {
    test_aes_exp_free(&skey1, &skey2);
    return -1;
  }

  const size_t sz_ekey = 15 * 16;

  memset(ekey, 0, sz_ekey);
  memcpy(ekey, buff, (dataSize > sz_ekey) ? sz_ekey : dataSize);

  IMB_AES_CMAC_SUBKEY_GEN_256(p_mgr, ekey, skey1, skey2);

  test_aes_exp_free(&skey1, &skey2);
  test_aes_exp_free(&ekey, &dkey);
  return 0;
}

static int test_imb_aes_keyexp_xcbc128(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  void *key2, *key3, *key, *key_dust;
  void *expkey, *expkey_dust;

  if (test_aes_exp_alloc(1, &key2, &key3) != 0)
    return -1;

  if (test_aes_exp_alloc(1, &key, &key_dust) != 0) {
    test_aes_exp_free(&key2, &key3);
    return -1;
  }

  if (test_aes_exp_alloc(11, &expkey, &expkey_dust) != 0) {
    test_aes_exp_free(&key2, &key3);
    test_aes_exp_free(&key, &key_dust);
    return -1;
  }

  memset(key, 0, 16);
  memcpy(key, buff, (dataSize > 16) ? 16 : dataSize);

  IMB_AES_XCBC_KEYEXP(p_mgr, key, expkey, key2, key3);

  test_aes_exp_free(&key2, &key3);
  test_aes_exp_free(&key, &key_dust);
  test_aes_exp_free(&expkey, &expkey_dust);
  return 0;
}

static int test_imb_des_keyexp(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  void *key = malloc(sizeof(uint64_t));

  if (key == NULL)
    return -1;

  void *expkey = malloc(IMB_DES_KEY_SCHED_SIZE);

  if (expkey == NULL) {
    free(key);
    return -1;
  }

  memset(key, 0, sizeof(uint64_t));
  memcpy(key, buff, (dataSize > sizeof(uint64_t)) ? sizeof(uint64_t) : dataSize);

  IMB_DES_KEYSCHED(p_mgr, expkey, key);

  free(key);
  free(expkey);
  return 0;
}

static int test_imb_sm4_keyexp(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  void *key = malloc(IMB_KEY_128_BYTES);
  if (key == NULL)
    return -1;

  fill_data(key, IMB_KEY_128_BYTES, buff, dataSize);

  void *ekey, *dkey;

  if (test_aes_exp_alloc((IMB_SM4_KEY_SCHEDULE_ROUNDS * 4) / 16, &ekey, &dkey) != 0) {
    free(key);
    return -1;
  }

  IMB_SM4_KEYEXP(p_mgr, key, ekey, dkey);
  test_aes_exp_free(&ekey, &dkey);
  free(key);
  return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static int test_imb_sha1(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  const size_t tag_sz = IMB_SHA1_DIGEST_SIZE_IN_BYTES;
  void *tag = malloc(tag_sz);

  if (tag == NULL)
    return -1;

  IMB_SHA1(p_mgr, buff, dataSize, tag);

  free(tag);
  return 0;
}

static int test_imb_sha224(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  const size_t tag_sz = IMB_SHA224_DIGEST_SIZE_IN_BYTES;
  void *tag = malloc(tag_sz);

  if (tag == NULL)
    return -1;

  IMB_SHA224(p_mgr, buff, dataSize, tag);

  free(tag);
  return 0;
}

static int test_imb_sha256(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  const size_t tag_sz = IMB_SHA256_DIGEST_SIZE_IN_BYTES;
  void *tag = malloc(tag_sz);

  if (tag == NULL)
    return -1;

  IMB_SHA256(p_mgr, buff, dataSize, tag);

  free(tag);
  return 0;
}

static int test_imb_sha384(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  const size_t tag_sz = IMB_SHA384_DIGEST_SIZE_IN_BYTES;
  void *tag = malloc(tag_sz);

  if (tag == NULL)
    return -1;

  IMB_SHA384(p_mgr, buff, dataSize, tag);

  free(tag);
  return 0;
}

static int test_imb_sha512(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  const size_t tag_sz = IMB_SHA512_DIGEST_SIZE_IN_BYTES;
  void *tag = malloc(tag_sz);

  if (tag == NULL)
    return -1;

  IMB_SHA512(p_mgr, buff, dataSize, tag);

  free(tag);
  return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static int test_imb_hec32(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  const size_t xgem_sz = 4;
  void *xgem = malloc(xgem_sz);

  if (xgem == NULL)
    return -1;

  fill_data(xgem, xgem_sz, buff, dataSize);

  IMB_HEC_32(p_mgr, xgem);

  free(xgem);
  return 0;
}

static int test_imb_hec64(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  const size_t xgem_sz = 8;
  void *xgem = malloc(xgem_sz);

  if (xgem == NULL)
    return -1;

  fill_data(xgem, xgem_sz, buff, dataSize);

  IMB_HEC_64(p_mgr, xgem);

  free(xgem);
  return 0;
}

/* ========================================================================== */
/* ========================================================================== */

struct test_hash_one_block {
  void *tag;
  void *block;
};

static void test_hash_one_block_free(struct test_hash_one_block *ts) {
  if (ts->tag != NULL)
    free(ts->tag);
  if (ts->block != NULL)
    free(ts->block);
  memset(ts, 0, sizeof(*ts));
}

static int test_hash_one_block_alloc(struct test_hash_one_block *ts, const size_t tag_size, const size_t block_size) {
  ts->tag = malloc(tag_size);
  ts->block = malloc(block_size);
  if (ts->tag == NULL || ts->block == NULL) {
    test_hash_one_block_free(ts);
    return -1;
  }
  return 0;
}

static int test_imb_sha1_one_block(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  struct test_hash_one_block ts;

  if (test_hash_one_block_alloc(&ts, IMB_SHA1_DIGEST_SIZE_IN_BYTES, IMB_SHA1_BLOCK_SIZE) != 0)
    return -1;

  fill_data(ts.block, IMB_SHA1_BLOCK_SIZE, buff, dataSize);

  IMB_SHA1_ONE_BLOCK(p_mgr, ts.block, ts.tag);

  test_hash_one_block_free(&ts);
  return 0;
}

static int test_imb_sha224_one_block(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  struct test_hash_one_block ts;

  if (test_hash_one_block_alloc(&ts, IMB_SHA256_DIGEST_SIZE_IN_BYTES, IMB_SHA_224_BLOCK_SIZE) != 0)
    return -1;

  fill_data(ts.block, IMB_SHA_224_BLOCK_SIZE, buff, dataSize);

  IMB_SHA224_ONE_BLOCK(p_mgr, ts.block, ts.tag);

  test_hash_one_block_free(&ts);
  return 0;
}

static int test_imb_sha256_one_block(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  struct test_hash_one_block ts;

  if (test_hash_one_block_alloc(&ts, IMB_SHA256_DIGEST_SIZE_IN_BYTES, IMB_SHA_256_BLOCK_SIZE) != 0)
    return -1;

  fill_data(ts.block, IMB_SHA_256_BLOCK_SIZE, buff, dataSize);

  IMB_SHA256_ONE_BLOCK(p_mgr, ts.block, ts.tag);

  test_hash_one_block_free(&ts);
  return 0;
}

static int test_imb_sha384_one_block(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  struct test_hash_one_block ts;

  if (test_hash_one_block_alloc(&ts, IMB_SHA512_DIGEST_SIZE_IN_BYTES, IMB_SHA_384_BLOCK_SIZE) != 0)
    return -1;

  fill_data(ts.block, IMB_SHA_384_BLOCK_SIZE, buff, dataSize);

  IMB_SHA384_ONE_BLOCK(p_mgr, ts.block, ts.tag);

  test_hash_one_block_free(&ts);
  return 0;
}

static int test_imb_sha512_one_block(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  struct test_hash_one_block ts;

  if (test_hash_one_block_alloc(&ts, IMB_SHA512_DIGEST_SIZE_IN_BYTES, IMB_SHA_512_BLOCK_SIZE) != 0)
    return -1;

  fill_data(ts.block, IMB_SHA_512_BLOCK_SIZE, buff, dataSize);

  IMB_SHA512_ONE_BLOCK(p_mgr, ts.block, ts.tag);

  test_hash_one_block_free(&ts);
  return 0;
}

static int test_imb_md5_one_block(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  struct test_hash_one_block ts;

  if (test_hash_one_block_alloc(&ts, IMB_MD5_DIGEST_SIZE_IN_BYTES, IMB_MD5_BLOCK_SIZE) != 0)
    return -1;

  fill_data(ts.block, IMB_MD5_BLOCK_SIZE, buff, dataSize);

  IMB_MD5_ONE_BLOCK(p_mgr, ts.block, ts.tag);

  test_hash_one_block_free(&ts);
  return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static int test_imb_hmac_ipad_opad(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  const struct {
    IMB_HASH_ALG hash;
    size_t digest_size;
  } htab[] = {
      {IMB_AUTH_HMAC_SHA_1, IMB_SHA1_DIGEST_SIZE_IN_BYTES}, {IMB_AUTH_HMAC_SHA_224, IMB_SHA256_DIGEST_SIZE_IN_BYTES}, {IMB_AUTH_HMAC_SHA_256, IMB_SHA256_DIGEST_SIZE_IN_BYTES}, {IMB_AUTH_HMAC_SHA_384, IMB_SHA512_DIGEST_SIZE_IN_BYTES}, {IMB_AUTH_HMAC_SHA_512, IMB_SHA512_DIGEST_SIZE_IN_BYTES}, {IMB_AUTH_MD5, IMB_MD5_DIGEST_SIZE_IN_BYTES}, {IMB_AUTH_GHASH, 1}, /* invalid */
  };
  const size_t index = dataSize > 0 ? (buff[0] % IMB_DIM(htab)) : 0;

  void *opad = malloc(htab[index].digest_size);

  if (opad == NULL)
    return -1;

  void *ipad = malloc(htab[index].digest_size);

  if (ipad == NULL) {
    free(opad);
    return -1;
  }

  imb_hmac_ipad_opad(p_mgr, htab[index].hash, buff, dataSize, ipad, opad);

  free(opad);
  free(ipad);
  return 0;
}

/* ========================================================================== */
/* ========================================================================== */

struct test_cfb_one_block {
  void *iv;
  void *expkey;
};

static void test_cfb_one_block_free(struct test_cfb_one_block *ts) {
  if (ts->iv != NULL)
    free(ts->iv);
  if (ts->expkey != NULL)
    free(ts->expkey);
  memset(ts, 0, sizeof(*ts));
}

static int test_cfb_one_block_alloc(struct test_cfb_one_block *ts, const size_t rounds, const int is_aes) {
  if (is_aes) {
    /* AES */
    ts->iv = malloc(16);
    ts->expkey = malloc(rounds * 16);
  } else {
    /* DES */
    ts->iv = malloc(8);
    ts->expkey = malloc(IMB_DES_KEY_SCHED_SIZE);
  }
  if (ts->iv == NULL || ts->expkey == NULL) {
    test_cfb_one_block_free(ts);
    return -1;
  }
  return 0;
}

static int test_imb_cfb128_one_block(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  struct test_cfb_one_block ts;
  const size_t aes_rounds = 11;

  if (test_cfb_one_block_alloc(&ts, aes_rounds, 1 /* AES */) != 0)
    return -1;

  fill_data(ts.iv, 16, buff, dataSize);
  fill_data(ts.expkey, aes_rounds * 16, buff, dataSize);

  IMB_AES128_CFB_ONE(p_mgr, buff, buff, ts.iv, ts.expkey, dataSize);

  test_cfb_one_block_free(&ts);
  return 0;
}

static int test_imb_cfb256_one_block(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  struct test_cfb_one_block ts;
  const size_t aes_rounds = 15;

  if (test_cfb_one_block_alloc(&ts, aes_rounds, 1 /* AES */) != 0)
    return -1;

  fill_data(ts.iv, 16, buff, dataSize);
  fill_data(ts.expkey, aes_rounds * 16, buff, dataSize);

  IMB_AES256_CFB_ONE(p_mgr, buff, buff, ts.iv, ts.expkey, dataSize);

  test_cfb_one_block_free(&ts);
  return 0;
}

static int test_imb_des_cfb_one_block(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  (void)p_mgr;

  struct test_cfb_one_block ts;

  if (test_cfb_one_block_alloc(&ts, 0, 0 /* DES */) != 0)
    return -1;

  fill_data(ts.iv, 8, buff, dataSize);
  fill_data(ts.expkey, IMB_DES_KEY_SCHED_SIZE, buff, dataSize);

  des_cfb_one(buff, buff, ts.iv, ts.expkey, dataSize);

  test_cfb_one_block_free(&ts);
  return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static int test_imb_set_session(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  IMB_JOB *job = malloc(sizeof(*job));

  if (job == NULL)
    return -1;
  fill_data(job, sizeof(*job), buff, dataSize);

  imb_set_session(p_mgr, job);
  free(job);
  return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static int test_imb_self_test_cb_fn(void *cb_arg, const IMB_SELF_TEST_CALLBACK_DATA *data) {
  (void)cb_arg;
  (void)data;
  return 0;
}

static int test_imb_self_test_set_cb(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  const size_t cb_arg_size = 8;
  void *cb_arg = malloc(cb_arg_size);

  if (cb_arg == NULL)
    return -1;

  fill_data(cb_arg, cb_arg_size, buff, dataSize);

  imb_self_test_set_cb(p_mgr, test_imb_self_test_cb_fn, cb_arg);
  imb_self_test_set_cb(p_mgr, NULL, NULL);

  free(cb_arg);
  return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static int test_imb_self_test_get_cb(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  (void)buff;
  (void)dataSize;

  imb_self_test_cb_t *cb_fn = malloc(sizeof(*cb_fn));

  if (cb_fn == NULL)
    return -1;

  void **cb_arg = malloc(sizeof(*cb_arg));

  if (cb_arg == NULL) {
    free(cb_fn);
    return -1;
  }

  (void)imb_self_test_get_cb(p_mgr, cb_fn, cb_arg);

  free(cb_fn);
  free(cb_arg);
  return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static int test_imb_get_strerror(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize) {
  (void)p_mgr;

  int *errnum = malloc(sizeof(*errnum));

  if (errnum == NULL)
    return -1;
  fill_data(errnum, sizeof(*errnum), buff, dataSize);

  imb_get_strerror(*errnum);

  free(errnum);
  return 0;
}

/* ========================================================================== */
/* ========================================================================== */

struct {
  int (*func)(IMB_MGR *mb_mgr, uint8_t *buff, size_t dataSize);
  const char *func_name;
} direct_apis[] = {
    {test_imb_aes_keyexp_128, "test_imb_aes_keyexp_128"},
    {test_imb_aes_keyexp_192, "test_imb_aes_keyexp_192"},
    {test_imb_aes_keyexp_256, "test_imb_aes_keyexp_256"},
    {test_imb_aes_subkey_cmac128, "test_imb_aes_subkey_cmac128"},
    {test_imb_aes_subkey_cmac256, "test_imb_aes_subkey_cmac256"},
    {test_imb_aes_keyexp_xcbc128, "test_imb_aes_keyexp_xcbc128"},
    {test_imb_des_keyexp, "test_imb_des_keyexp"},
    {test_imb_sm4_keyexp, "test_imb_sm4_keyexp"},

    {test_imb_sha1, "test_imb_sha1"},
    {test_imb_sha224, "test_imb_sha224"},
    {test_imb_sha256, "test_imb_sha256"},
    {test_imb_sha384, "test_imb_sha384"},
    {test_imb_sha512, "test_imb_sha512"},

    {test_imb_sha1_one_block, "test_imb_sha1_one_block"},
    {test_imb_sha224_one_block, "test_imb_sha224_one_block"},
    {test_imb_sha256_one_block, "test_imb_sha256_one_block"},
    {test_imb_sha384_one_block, "test_imb_sha384_one_block"},
    {test_imb_sha512_one_block, "test_imb_sha512_one_block"},
    {test_imb_md5_one_block, "test_imb_md5_one_block"},

    {test_imb_hmac_ipad_opad, "test_imb_hmac_ipad_opad"},

    {test_imb_cfb128_one_block, "test_imb_cfb128_one_block"},
    {test_imb_cfb256_one_block, "test_imb_cfb256_one_block"},
    {test_imb_des_cfb_one_block, "test_imb_des_cfb_one_block"},

    {test_snow3g_init_key_sched, "test_snow3g_init_key_sched"},
    {test_snow3g_f8_1_buff_bit, "test_snow3g_f8_1_buff_bit"},
    {test_snow3g_f8_1_buff, "test_snow3g_f8_1_buff"},
    {test_snow3g_f8_2_buff, "test_snow3g_f8_2_buff"},
    {test_snow3g_f8_4_buff, "test_snow3g_f8_4_buff"},
    {test_snow3g_f8_8_buff, "test_snow3g_f8_8_buff"},
    {test_snow3g_f8_n_buff, "test_snow3g_f8_n_buff"},
    {test_snow3g_f8_8_multikey, "test_snow3g_f8_8_multikey"},
    {test_snow3g_f8_n_multikey, "test_snow3g_f8_n_multikey"},
    {test_snow3g_f8_iv_gen, "test_snow3g_f8_iv_gen"},
    {test_snow3g_f9_1_buff, "test_snow3g_f9_1_buff"},
    {test_snow3g_f9_iv_gen, "test_snow3g_f9_iv_gen"},

    {test_aes_gcm_pre, "test_aes_gcm_pre"},
    {test_aes_gcm_precomp, "test_aes_gcm_precomp"},
    {test_aes128_gcm_enc_sgl, "test_aes128_gcm_enc_sgl"},
    {test_aes128_gcm_dec_sgl, "test_aes128_gcm_dec_sgl"},
    {test_aes192_gcm_enc_sgl, "test_aes192_gcm_enc_sgl"},
    {test_aes192_gcm_dec_sgl, "test_aes192_gcm_dec_sgl"},
    {test_aes256_gcm_enc_sgl, "test_aes256_gcm_enc_sgl"},
    {test_aes256_gcm_dec_sgl, "test_aes256_gcm_dec_sgl"},
    {test_aes128_gcm_enc, "test_aes128_gcm_enc"},
    {test_aes128_gcm_dec, "test_aes128_gcm_dec"},
    {test_aes192_gcm_enc, "test_aes192_gcm_enc"},
    {test_aes192_gcm_dec, "test_aes192_gcm_dec"},
    {test_aes256_gcm_enc, "test_aes256_gcm_enc"},
    {test_aes256_gcm_dec, "test_aes256_gcm_dec"},
    {test_aes128_gcm_init_var_iv, "test_aes128_gcm_init_var_iv"},
    {test_aes192_gcm_init_var_iv, "test_aes192_gcm_init_var_iv"},
    {test_aes256_gcm_init_var_iv, "test_aes256_gcm_init_var_iv"},

    {test_aes128_gmac, "test_aes128_gmac"},
    {test_aes192_gmac, "test_aes192_gmac"},
    {test_aes256_gmac, "test_aes256_gmac"},

    {test_ghash, "test_ghash"},
    {test_ghash_pre, "test_ghash_pre"},

    {test_zuc_eea3_1_buff, "test_zuc_eea3_1_buff"},
    {test_zuc_eea3_4_buff, "test_zuc_eea3_4_buff"},
    {test_zuc_eea3_n_buff, "test_zuc_eea3_n_buff"},
    {test_zuc_eea3_iv_gen, "test_zuc_eea3_iv_gen"},
    {test_zuc_eia3_1_buff, "test_zuc_eia3_1_buff"},
    {test_zuc_eia3_n_buff, "test_zuc_eia3_n_buff"},
    {test_zuc_eia3_iv_gen, "test_zuc_eia3_iv_gen"},

    {test_chacha_poly_enc, "test_chacha_poly_enc"},
    {test_chacha_poly_dec, "test_chacha_poly_dec"},

    {test_crc32_ethernet_fcs, "test_crc32_ethernet_fcs"},
    {test_crc16_x25, "test_crc16_x25"},
    {test_crc32_sctp, "test_crc32_sctp"},
    {test_crc16_fp_data, "test_crc16_fp_data"},
    {test_crc11_fp_header, "test_crc11_fp_header"},
    {test_crc24_lte_a, "test_crc24_lte_a"},
    {test_crc24_lte_b, "test_crc24_lte_b"},
    {test_crc7_fp_header, "test_crc7_fp_header"},
    {test_crc10_iuup_data, "test_crc10_iuup_data"},
    {test_crc6_iuup_header, "test_crc6_iuup_header"},
    {test_crc32_wimax_ofdma_data, "test_crc32_wimax_ofdma_data"},
    {test_crc8_wimax_ofdma_hcs, "test_crc8_wimax_ofdma_hcs"},

    {test_kasumi_f8_init_key_sched, "test_kasumi_f8_init_key_sched"},
    {test_kasumi_f8_1_buff_bit, "test_kasumi_f8_1_buff_bit"},
    {test_kasumi_f8_1_buff, "test_kasumi_f8_1_buff"},
    {test_kasumi_f8_2_buff, "test_kasumi_f8_2_buff"},
    {test_kasumi_f8_3_buff, "test_kasumi_f8_3_buff"},
    {test_kasumi_f8_4_buff, "test_kasumi_f8_4_buff"},
    {test_kasumi_f8_n_buff, "test_kasumi_f8_n_buff"},
    {test_kasumi_f8_iv_gen, "test_kasumi_f8_iv_gen"},
    {test_kasumi_f9_1_buff, "test_kasumi_f9_1_buff"},
    {test_kasumi_f9_1_buff_user, "test_kasumi_f9_1_buff_user"},
    {test_kasumi_f9_init_key_sched, "test_kasumi_f9_init_key_sched"},
    {test_kasumi_f9_iv_gen, "test_kasumi_f9_iv_gen"},

    {test_imb_clear_mem, "test_imb_clear_mem"},

    {test_imb_quic_aes_gcm, "test_imb_quic_aes_gcm"},
    {test_imb_quic_chacha20_poly1305, "test_imb_quic_chacha20_poly1305"},
    {test_imb_quic_hp_aes_ecb, "test_imb_quic_hp_aes_ecb"},
    {test_imb_quic_hp_chacha20, "test_imb_quic_hp_chacha20"},

    {test_imb_set_session, "test_imb_set_session"},
    {test_imb_self_test_set_cb, "test_imb_self_test_set_cb"},
    {test_imb_self_test_get_cb, "test_imb_self_test_get_cb"},
    {test_imb_get_strerror, "test_imb_get_strerror"},

    {test_imb_hec32, "test_imb_hec32"},
    {test_imb_hec64, "test_imb_hec64"},
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t dataSize) {
  static IMB_MGR *p_mgr = NULL;

  if (dataSize < sizeof(int))
    return -1;

  const size_t newDataSize = dataSize - sizeof(int);
  uint8_t *buff = malloc(newDataSize);

  if (buff == NULL)
    return -1;

  memcpy(buff, &data[sizeof(int)], newDataSize);

  /* allocate multi-buffer manager */
  if (p_mgr == NULL) {
    p_mgr = alloc_mb_mgr(flags);
    if (p_mgr == NULL) {
      printf("Error allocating MB_MGR structure!\n");
      free(buff);
      return -1;
    }

    IMB_ARCH arch_to_run = IMB_ARCH_NUM;

    if (arch == IMB_ARCH_SSE)
      init_mb_mgr_sse(p_mgr);
    else if (arch == IMB_ARCH_AVX)
      init_mb_mgr_avx(p_mgr);
    else if (arch == IMB_ARCH_AVX2)
      init_mb_mgr_avx2(p_mgr);
    else if (arch == IMB_ARCH_AVX512)
      init_mb_mgr_avx512(p_mgr);
    else
      init_mb_mgr_auto(p_mgr, &arch_to_run);
  }

  const int idx = ((const int *)data)[0] % DIM(direct_apis);
  const int ret = direct_apis[idx].func(p_mgr, buff, newDataSize);

  free(buff);
  return ret;
}
