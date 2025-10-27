/* Fuzz testing target. */
/*
 * Copyright (c) 2022 Genome Research Ltd.
 * Author(s): Rob Davies
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *
 *    3. Neither the names Genome Research Ltd and Wellcome Trust Sanger
 *       Institute nor the names of its contributors may be used to endorse
 *       or promote products derived from this software without specific
 *       prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY GENOME RESEARCH LTD AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL GENOME RESEARCH
 * LTD OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <config.h>

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "htscodecs/arith_dynamic.h"
#include "htscodecs/rANS_static.h"
#include "htscodecs/rANS_static32x16pr.h"
#include "htscodecs/rANS_static4x16.h"

int LLVMFuzzerTestOneInput(uint8_t *in, size_t in_size) {

  const int order_a[] = {
      0,    1,    // No extras
      0x40, 041,  // RANS_ORDER_RLE
      0x80, 0x81, // RANS_ORDER_PACK
      0xc0, 0xc1, // RANS_ORDER_RLE|RANS_ORDER_PACK
  };

#if defined(__x86_64__)
  const int cpu_enc_a[] = {0, RANS_CPU_ENC_SSE4, RANS_CPU_ENC_AVX2, RANS_CPU_ENC_AVX512};
  const int cpu_dec_a[] = {0, RANS_CPU_DEC_SSE4, RANS_CPU_DEC_AVX2, RANS_CPU_DEC_AVX512};
#elif defined(__ARM_NEON) && defined(__aarch64__)
  const int cpu_enc_a[] = {0, RANS_CPU_ENC_NEON};
  const int cpu_dec_a[] = {0, RANS_CPU_DEC_NEON};
#else
  const int cpu_enc_a[] = {0};
  const int cpu_dec_a[] = {0};
#endif
  int i;

  if (in_size > 200000)
    return -1;

  // rans_compress() only supports order 0 and 1
  for (i = 0; i < 1; i++) {
    uint8_t *comp, *uncomp;
    uint32_t csize, usize;
    comp = rans_compress(in, in_size, &csize, i);
    if (!comp)
      abort();
    uncomp = rans_uncompress(comp, csize, &usize);
    if (!uncomp)
      abort();
    if (usize != in_size)
      abort();
    if (memcmp(uncomp, in, in_size) != 0)
      abort();
    free(comp);
    free(uncomp);
  }

  for (i = 0; i < sizeof(order_a) / sizeof(*order_a); i++) {
    int order = order_a[i];
    uint8_t *comp, *uncomp, *comp0 = NULL;
    uint32_t csize, usize, csize0 = 0;
    int c;
    comp = rans_compress_4x16(in, in_size, &csize, order);
    if (!comp)
      abort();
    uncomp = rans_uncompress_4x16(comp, csize, &usize);
    if (!uncomp)
      abort();
    if (usize != in_size)
      abort();
    if (memcmp(uncomp, in, in_size) != 0)
      abort();
    free(comp);
    free(uncomp);

    comp = arith_compress(in, in_size, &csize, order);
    if (!comp)
      abort();
    uncomp = arith_uncompress(comp, csize, &usize);
    if (!uncomp)
      abort();
    if (usize != in_size)
      abort();
    if (memcmp(uncomp, in, in_size) != 0)
      abort();
    free(comp);
    free(uncomp);

    // Check all SIMD variants for RANS_ORDER_X32
    for (c = 0; c < sizeof(cpu_enc_a) / sizeof(*cpu_enc_a); c++) {
      rans_set_cpu(cpu_enc_a[c]);
      comp = rans_compress_4x16(in, in_size, &csize, order | RANS_ORDER_X32);
      if (!comp)
        abort();
      if (comp0) {
        if (csize != csize0 || memcmp(comp0, comp, csize) != 0) {
          fprintf(stderr, "Compressed data mismatch order 0x%x cpu 0x%x\n", order, cpu_enc_a[c]);
          abort();
        }
        free(comp);
      } else {
        comp0 = comp;
        csize0 = csize;
      }
    }
    for (c = 0; c < sizeof(cpu_dec_a) / sizeof(*cpu_dec_a); c++) {
      rans_set_cpu(cpu_dec_a[c]);
      uncomp = rans_uncompress_4x16(comp0, csize0, &usize);
      if (!uncomp)
        abort();
      if (usize != in_size || memcmp(uncomp, in, in_size) != 0) {
        fprintf(stderr, "Uncompressed data mismatch order 0x%x cpu 0x%x\n", order, cpu_dec_a[c]);
        abort();
      }
      free(uncomp);
    }
    free(comp0);
  }
  return 0;
}
