/*
 * xdiff.cc - fuzzer harness for thirdparty/xdiff
 *
 * Copyright 2018, Google Inc.
 *
 * This software may be used and distributed according to the terms of
 * the GNU General Public License, incorporated herein by reference.
 */
#include "thirdparty/xdiff/xdiff.h"
#include <inttypes.h>
#include <stdlib.h>

#include "FuzzedDataProvider.h"

extern "C" {

int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }

int hunk_consumer(long a1, long a2, long b1, long b2, void *priv) {
  // TODO: probably also test returning -1 from this when things break?
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  // Don't allow fuzzer inputs larger than 100k, since we'll just bog
  // down and not accomplish much.
  if (Size > 100000) {
    return 0;
  }
  FuzzedDataProvider provider(Data, Size);
  std::string left = provider.ConsumeRandomLengthString(Size);
  std::string right = provider.ConsumeRemainingBytesAsString();
  mmfile_t a, b;

  a.ptr = (char *)left.c_str();
  a.size = left.size();
  b.ptr = (char *)right.c_str();
  b.size = right.size();
  xpparam_t xpp = {
      XDF_INDENT_HEURISTIC, /* flags */
  };
  xdemitconf_t xecfg = {
      XDL_EMIT_BDIFFHUNK, /* flags */
      hunk_consumer,      /* hunk_consume_func */
  };
  xdemitcb_t ecb = {
      NULL, /* priv */
  };
  xdl_diff(&a, &b, &xpp, &xecfg, &ecb);
  return 0; // Non-zero return values are reserved for future use.
}

} // extern "C"
