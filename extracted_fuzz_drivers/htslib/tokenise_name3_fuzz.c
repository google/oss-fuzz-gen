/* Fuzz testing target. */
/*
 * Copyright (c) 2019,2020 Genome Research Ltd.
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "htscodecs/tokenise_name3.h"

int LLVMFuzzerTestOneInput(uint8_t *in, size_t in_size) {
  unsigned int uncomp_size;
  unsigned char *uncomp = tok3_decode_names(in, in_size, &uncomp_size);
  if (uncomp)
    free(uncomp);

  return 0;
}

#ifdef NOFUZZ
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>

#define BS 1024 * 1024
static unsigned char *load(char *fn, uint64_t *lenp) {
  unsigned char *data = NULL;
  uint64_t dsize = 0;
  uint64_t dcurr = 0;
  signed int len;
  int fd = open(fn, O_RDONLY);

  do {
    if (dsize - dcurr < BS) {
      dsize = dsize ? dsize * 2 : BS;
      data = realloc(data, dsize);
    }

    len = read(fd, data + dcurr, BS);
    if (len > 0)
      dcurr += len;
  } while (len > 0);

  if (len == -1) {
    perror("read");
  }

  close(fd);
  *lenp = dcurr;
  return data;
}

int main(int argc, char **argv) {
  uint64_t in_size;
  unsigned char *in = load(argv[1], &in_size);

  LLVMFuzzerTestOneInput(in, in_size);

  free(in);
  return 0;
}
#endif
