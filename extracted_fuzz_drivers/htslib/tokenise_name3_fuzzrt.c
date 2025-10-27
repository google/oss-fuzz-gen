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
 *    Institute nor the names of its contributors may be used to endorse
 *    or promote products derived from this software without specific
 *    prior written permission.
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

// Round-trip fuzz testing.  While tokenise_name3_fuzz.c tests the name
// decoder when given random input, this tests it can encode and then
// (if an error isn't reported) decode and get back the same content.
//
// It's complicated as we need to construct meta-data for how many names
// we have.
#include "config.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "htscodecs/tokenise_name3.h"

int LLVMFuzzerTestOneInput(const uint8_t *in, size_t in_sz) {
  int level, arith;
  char in2[8192];

  // 4096 is default max size for libfuzzer anyway
  if (in_sz > 8192)
    return -1;

  // Turn newlines to nuls so we can do round-trip testing
  // on multi-name data.
  int i;
  for (i = 0; i < in_sz; i++)
    in2[i] = in[i] == '\n' ? 0 : in[i];
  if (in_sz && in2[in_sz - 1] > '\n')
    in2[in_sz++] = 0;

  for (arith = 0; arith < 2; arith++) {
    for (level = 1; level <= 9; level += 8) { // 1 & 9 only
      int clen;
      uint8_t *cdat = tok3_encode_names((char *)in2, in_sz, level, arith, &clen, NULL);
      if (!cdat)
        // skip this input from corpus as it's unparseable
        return -1;

      uint32_t ulen;
      uint8_t *udat = tok3_decode_names(cdat, clen, &ulen);
      if (!udat || ulen != in_sz)
        abort();

      if (memcmp(in2, udat, ulen) != 0)
        abort();

      free(cdat);
      free(udat);
    }
  }

  return 0;
}
