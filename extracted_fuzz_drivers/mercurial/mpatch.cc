/*
 * mpatch.cc - fuzzer harness for mpatch.c
 *
 * Copyright 2018, Google Inc.
 *
 * This software may be used and distributed according to the terms of
 * the GNU General Public License, incorporated herein by reference.
 */
#include <iostream>
#include <memory>
#include <stdint.h>
#include <stdlib.h>
#include <vector>

#include "fuzzutil.h"

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }

// To avoid having too many OOMs from the fuzzer infrastructure, we'll
// skip patch application if the resulting fulltext would be bigger
// than 10MiB.
#define MAX_OUTPUT_SIZE 10485760

extern "C" {
#include "bitmanipulation.h"
#include "mpatch.h"

struct mpatchbin {
  std::unique_ptr<char[]> data;
  size_t len;
};

static mpatch_flist *getitem(void *vbins, ssize_t pos) {
  std::vector<mpatchbin> *bins = (std::vector<mpatchbin> *)vbins;
  const mpatchbin &bin = bins->at(pos + 1);
  struct mpatch_flist *res;
  LOG(2) << "mpatch_decode " << bin.len << std::endl;
  if (mpatch_decode(bin.data.get(), bin.len, &res) < 0)
    return NULL;
  return res;
}

// input format:
// u8 number of inputs
// one u16 for each input, its length
// the inputs
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (!Size) {
    return 0;
  }
  // First byte of data is how many texts we expect, first text
  // being the base the rest being the deltas.
  ssize_t numtexts = Data[0];
  if (numtexts < 2) {
    // No point if we don't have at least a base text and a delta...
    return 0;
  }
  // Each text will be described by a byte for how long it
  // should be, so give up if we don't have enough.
  if ((Size - 1) < (numtexts * 2)) {
    return 0;
  }
  size_t consumed = 1 + (numtexts * 2);
  LOG(2) << "input contains " << Size << std::endl;
  LOG(2) << numtexts << " texts, consuming " << consumed << std::endl;
  std::vector<mpatchbin> bins;
  bins.reserve(numtexts);
  for (int i = 0; i < numtexts; ++i) {
    mpatchbin bin;
    size_t nthsize = getbeuint16((char *)Data + 1 + (2 * i));
    LOG(2) << "text " << i << " is " << nthsize << std::endl;
    char *start = (char *)Data + consumed;
    consumed += nthsize;
    if (consumed > Size) {
      LOG(2) << "ran out of data, consumed " << consumed << " of " << Size << std::endl;
      return 0;
    }
    bin.len = nthsize;
    bin.data.reset(new char[nthsize]);
    memcpy(bin.data.get(), start, nthsize);
    bins.push_back(std::move(bin));
  }
  LOG(2) << "mpatch_flist" << std::endl;
  struct mpatch_flist *patch = mpatch_fold(&bins, getitem, 0, numtexts - 1);
  if (!patch) {
    return 0;
  }
  LOG(2) << "mpatch_calcsize" << std::endl;
  ssize_t outlen = mpatch_calcsize(bins[0].len, patch);
  LOG(2) << "outlen " << outlen << std::endl;
  if (outlen < 0 || outlen > MAX_OUTPUT_SIZE) {
    goto cleanup;
  }
  {
    char *dest = (char *)malloc(outlen);
    LOG(2) << "expecting " << outlen << " total bytes at " << (void *)dest << std::endl;
    mpatch_apply(dest, bins[0].data.get(), bins[0].len, patch);
    free(dest);
    LOG(1) << "applied a complete patch" << std::endl;
  }
cleanup:
  mpatch_lfree(patch);
  return 0;
}

} // extern "C"
