/*  test/fuzz/hts_open_fuzzer.c -- Fuzz driver for hts_open.

    Copyright (C) 2018 Google LLC.
    Copyright (C) 2019-2020, 2023 Genome Research Ltd.

    Author: Markus Kusano <kusano@google.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.  */

#include <config.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../htslib/hfile.h"
#include "../../htslib/hts.h"
#include "../../htslib/sam.h"
#include "../../htslib/vcf.h"

static void hts_close_or_abort(htsFile *file) {
  if (hts_close(file) != 0) {
    abort();
  }
}

static void view_sam(const uint8_t *data, size_t size, char *mode, int close_abort) {
  uint8_t *copy = malloc(size);
  if (copy == NULL) {
    abort();
  }
  memcpy(copy, data, size);

  hFILE *memfile = hopen("mem:", "rb:", copy, size);
  if (memfile == NULL) {
    free(copy);
    return;
  }

  htsFile *in = hts_hopen(memfile, "data", "rb");
  if (in == NULL) {
    if (hclose(memfile) != 0)
      abort();
    return;
  }

  samFile *out = sam_open("/dev/null", mode);
  if (!out)
    abort();

#ifdef FUZZ_FAI
  // Not critical if this doesn't work, but can test more if
  // we're in the right location.
  //
  // We can't rely on what the pwd is for the OSS-fuzz so we don't enable
  // this by default.
  if (hts_set_fai_filename(out, "../c2.fa") < 0) {
    static int warned = 0;
    if (!warned) {
      warned = 1;
      fprintf(stderr, "Warning couldn't find the c2.fa file\n");
    }
  }
#endif

  sam_hdr_t *hdr = sam_hdr_read(in);
  if (hdr == NULL) {
    if (close_abort)
      hts_close_or_abort(out);
    else
      hts_close(out);
    hts_close(in);
    return;
  }

  // This will force the header to be parsed.
  (void)sam_hdr_count_lines(hdr, "SQ");

  if (sam_hdr_write(out, hdr) != 0)
    goto err;

  bam1_t *b = bam_init1();
  if (b == NULL)
    goto err;

  while (sam_read1(in, hdr, b) >= 0) {
    if (sam_write1(out, hdr, b) < 0)
      break;
  }
  bam_destroy1(b);

err:
  sam_hdr_destroy(hdr);
  if (close_abort)
    hts_close_or_abort(out);
  else
    hts_close(out);
  hts_close(in);
}

static void view_vcf(const uint8_t *data, size_t size, char *mode) {
  uint8_t *copy = malloc(size);
  if (copy == NULL) {
    abort();
  }
  memcpy(copy, data, size);

  hFILE *memfile = hopen("mem:", "rb:", copy, size);
  if (memfile == NULL) {
    free(copy);
    return;
  }

  htsFile *in = hts_hopen(memfile, "data", "rb");
  if (in == NULL) {
    if (hclose(memfile) != 0)
      abort();
    return;
  }

  vcfFile *out = vcf_open("/dev/null", mode);
  if (!out)
    abort();

  bcf_hdr_t *hdr = bcf_hdr_read(in);
  if (hdr == NULL) {
    hts_close_or_abort(out);
    hts_close(in);
    return;
  }

  if (bcf_hdr_write(out, hdr) != 0)
    goto err;

  bcf1_t *rec = bcf_init();
  if (rec == NULL)
    goto err;

  while (bcf_read(in, hdr, rec) >= 0) {
    if (bcf_write(out, hdr, rec) < 0)
      break;
  }
  bcf_destroy(rec);

err:
  bcf_hdr_destroy(hdr);
  hts_close_or_abort(out);
  hts_close(in);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Only data as a mem file purely for purposes of determining format
  hFILE *memfile;
  uint8_t *copy = malloc(size);
  if (copy == NULL) {
    abort();
  }
  memcpy(copy, data, size);
  // hopen does not take ownership of `copy`, but hts_hopen does.
  memfile = hopen("mem:", "rb:", copy, size);
  if (memfile == NULL) {
    free(copy);
    return 0;
  }

  htsFile *ht_file = hts_hopen(memfile, "data", "rb");
  if (ht_file == NULL) {
    if (hclose(memfile) != 0) {
      abort();
    }
    return 0;
  }
  int ftype = ht_file->format.category;
  hts_close(ht_file);

  // Now repeat a read-write loop multiple times per input, testing
  // encoding in all output formats.
  // (Although we could just ignore ftype and do all 5 for all inputs)
  switch (ftype) {
  case sequence_data:
    view_sam(data, size, "w", 1);  // SAM
    view_sam(data, size, "wb", 1); // BAM
    view_sam(data, size, "wc", 0); // CRAM
    break;
  case variant_data:
    view_vcf(data, size, "w");  // VCF
    view_vcf(data, size, "wb"); // BCF
    break;
  default:
    break;
  }
  return 0;
}
