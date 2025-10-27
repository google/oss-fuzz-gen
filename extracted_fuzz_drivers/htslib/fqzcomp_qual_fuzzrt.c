/* Fuzz testing target. */
/*
 * Copyright (c) 2023 Genome Research Ltd.
 * Author(s): James Bonfield
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
#include "config.h"

#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "htscodecs/fqzcomp_qual.h"

#ifndef MAX_REC
#define MAX_REC 5000
#endif

#ifndef MAX_SEQ
#define MAX_SEQ 5000
#endif

static unsigned int slice_len[MAX_REC];
static unsigned int slice_flags[MAX_REC];

static fqz_slice fixed_slice = {0};

fqz_slice *fake_slice(size_t buf_len, int nrec) {
  fixed_slice.len = slice_len;
  fixed_slice.flags = slice_flags;
  fixed_slice.num_records = nrec;

  // 1 long record
  if (nrec == 1) {
    slice_len[0] = buf_len;
    slice_flags[0] = 0; // FIXME
    return &fixed_slice;
  }

  // N 1-byte records
  if (nrec == buf_len) {
    int i;
    for (i = 0; i < buf_len; i++) {
      slice_len[i] = 1;
      slice_flags[i] = 0; // FIXME
    }
    return &fixed_slice;
  }

  // Otherwise variable length records

  // Reproducability of randomness
  int seed = rand();
  srand(0);

  int nlen = buf_len / 10 + 1;
  int i, l, n = 0;
  for (i = 0; i < buf_len; i += l, n++) {
    l = rand() % (nlen + 1);
    l += l == 0;
    slice_len[n] = i + l < buf_len ? l : buf_len - i;
    slice_flags[n] = 0; // FIXME
  }
  fixed_slice.num_records = n;

  srand(seed); // new random state

  return &fixed_slice;
}

int LLVMFuzzerTestOneInput(uint8_t *in, size_t in_size) {
  size_t c_size, u_size;

  int mode = 0;
  for (mode = 0; mode < 3; mode++) {
    int mval[3] = {0, 1, in_size};
    fqz_slice *s = fake_slice(in_size, mval[mode]);

    // Semi random strat, but based on a few bits of input data
    // for reproducability.
    // This lets the fuzzer explore the parameter space itself.
    int strat = in_size ? in[0] & 3 : 0;
    char *comp = fqz_compress(3, s, (char *)in, in_size, &c_size, strat, NULL);
    if (!comp) {
      fprintf(stderr, "REJECT FQZ %d to (null)n", (int)in_size);
      return -1;
    }

    char *uncomp = fqz_decompress(comp, c_size, &u_size, NULL, 0);
    if (!uncomp)
      abort();

    if (in_size != u_size)
      abort();

    if (memcmp(uncomp, in, in_size) != 0)
      abort();

    free(comp);
    free(uncomp);
  }

  return 0;
}
