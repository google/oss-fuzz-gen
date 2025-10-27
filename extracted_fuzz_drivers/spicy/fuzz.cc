// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>

#include <hilti/rt/exception.h>
#include <hilti/rt/init.h>
#include <hilti/rt/types/reference.h>
#include <hilti/rt/types/stream.h>
#include <hilti/rt/util.h>

#include <spicy/rt/init.h>
#include <spicy/rt/parsed-unit.h>
#include <spicy/rt/parser.h>

#ifndef SPICY_FUZZ_PARSER
#error "SPICY_FUZZ_PARSER needs to be defined"
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  static const spicy::rt::Parser *parser = nullptr;

  if (!parser) {
    hilti::rt::init();
    spicy::rt::init();

    for (auto *p : spicy::rt::parsers()) {
      parser = p;
      if (p->name == SPICY_FUZZ_PARSER)
        break;
    }
  }

  assert(parser);

  hilti::rt::ValueReference<hilti::rt::Stream> stream;
  stream->append(reinterpret_cast<const char *>(Data), Size);

  hilti::rt::ValueReference<spicy::rt::ParsedUnit> pu;

  try {
    if (parser->parse1)
      parser->parse1(stream, {}, {});
    else if (parser->parse3)
      parser->parse3(pu, stream, {}, {});
  } catch (...) {
  }

  return 0; // Non-zero return values are reserved for future use.
}

extern "C" int LLVMFuzzerRunDriver(int *argc, char ***argv, int (*UserCb)(const uint8_t *Data, size_t Size));

// We provide our own `main` to avoid linking to hilti-rt's weak `main` symbol.
int main(int argc, char **argv) { LLVMFuzzerRunDriver(&argc, &argv, LLVMFuzzerTestOneInput); }
