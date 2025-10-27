// Copyright (c) 2016-2017 The OTS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>
#ifndef OTS_FUZZER_NO_MAIN
#include <fstream>
#include <iostream>
#include <iterator>
#endif

#include "opentype-sanitiser.h"
#include "ots-memory-stream.h"
#include "ots.h"

namespace {

class Context : public ots::OTSContext {
public:
  Context() {}
  void Message(int, const char *, ...) {}
};

} // namespace

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  Context context;
  ots::ExpandingMemoryStream stream(size /*initial*/, size * 8 /*limit*/);
  bool ok = context.Process(&stream, data, size);

  if (ok) {
    ots::Buffer file(data, size);
    uint32_t tag;
    if (file.ReadU32(&tag) && tag == OTS_TAG('t', 't', 'c', 'f')) {
      uint32_t num_fonts;
      if (file.Skip(sizeof(uint32_t)) && file.ReadU32(&num_fonts)) {
        for (uint32_t i = 0; i < num_fonts; i++) {
          stream.Seek(0);
          context.Process(&stream, data, size, i);
        }
      }
    }
  }

  return 0;
}

#ifndef OTS_FUZZER_NO_MAIN
int main(int argc, char **argv) {
  for (int i = 1; i < argc; i++) {
    std::cout << argv[i] << std::endl;

    std::ifstream f(argv[i], std::ifstream::binary);
    if (!f.good())
      return 1;

    std::string s((std::istreambuf_iterator<char>(f)), (std::istreambuf_iterator<char>()));
    LLVMFuzzerTestOneInput((const uint8_t *)s.data(), s.size());
  }
  return 0;
}
#endif
