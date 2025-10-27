// DriverInternals.cpp
//
//   Implementation of DriverInternals.
//
// Copyright 2018-2019 by
// Armin Hasitzka.
//
// This file is part of the FreeType project, and may only be used,
// modified, and distributed under the terms of the FreeType project
// license, LICENSE.TXT.  By continuing to use, modify, or distribute
// this file you indicate that you have read the license and
// understand and accept it fully.

#include "driver/DriverInternals.h"

#include <iostream>

#include "targets/font-drivers/bdf-render.h"
#include "targets/font-drivers/bdf.h"

#include "targets/font-drivers/cff-ftengine.h"
#include "targets/font-drivers/cff-render-ftengine.h"
#include "targets/font-drivers/cff-render.h"
#include "targets/font-drivers/cff.h"

#include "targets/font-drivers/cidtype1-ftengine.h"
#include "targets/font-drivers/cidtype1-render-ftengine.h"
#include "targets/font-drivers/cidtype1-render.h"
#include "targets/font-drivers/cidtype1.h"

#include "targets/font-drivers/colrv1.h"

#include "targets/font-drivers/pcf-render.h"
#include "targets/font-drivers/pcf.h"

#include "targets/font-drivers/truetype-render-i35.h"
#include "targets/font-drivers/truetype-render-i38.h"
#include "targets/font-drivers/truetype-render.h"
#include "targets/font-drivers/truetype.h"

#include "targets/font-drivers/type1-ftengine.h"
#include "targets/font-drivers/type1-render-ftengine.h"
#include "targets/font-drivers/type1-render-tar.h"
#include "targets/font-drivers/type1-render.h"
#include "targets/font-drivers/type1-tar.h"
#include "targets/font-drivers/type1.h"

#include "targets/font-drivers/type42-render.h"
#include "targets/font-drivers/type42.h"

#include "targets/font-drivers/windowsfnt-render.h"
#include "targets/font-drivers/windowsfnt.h"

#include "targets/glyphs/bitmaps-pcf.h"
#include "targets/glyphs/outlines.h"

#include "targets/support/Bzip2FuzzTarget.h"
#include "targets/support/GzipFuzzTarget.h"
#include "targets/support/LzwFuzzTarget.h"

// The legacy fuzzer is a monolith but it is the only target that calls
// LLVMFuzzerTestOneInput( ... ) directly which is why we get away with
// using it to invoke the legacy target.

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

freetype::DriverInternals::DriverInternals() {
  (void)add<BdfFuzzTarget>("bdf");
  (void)add<BdfRenderFuzzTarget>("bdf-render");

  (void)add<CffFuzzTarget>("cff");
  (void)add<CffFtEngineFuzzTarget>("cff-ftengine");
  (void)add<CffRenderFuzzTarget>("cff-render");
  (void)add<CffRenderFtEngineFuzzTarget>("cff-render-ftengine");

  (void)add<CidType1FuzzTarget>("cidtype1");
  (void)add<CidType1FtEngineFuzzTarget>("cidtype1-ftengine");
  (void)add<CidType1RenderFuzzTarget>("cidtype1-render");
  (void)add<CidType1RenderFtEngineFuzzTarget>("cidtype1-render-ftengine");

  (void)add<ColrV1FuzzTarget>("colrv1");

  (void)add<PcfFuzzTarget>("pcf");
  (void)add<PcfRenderFuzzTarget>("pcf-render");

  (void)add<TrueTypeFuzzTarget>("truetype");
  (void)add<TrueTypeRenderFuzzTarget>("truetype-render");
  (void)add<TrueTypeRenderI35FuzzTarget>("truetype-render-i35");
  (void)add<TrueTypeRenderI38FuzzTarget>("truetype-render-i38");

  (void)add<Type1FuzzTarget>("type1");
  (void)add<Type1FtEngineFuzzTarget>("type1-ftengine");
  (void)add<Type1RenderFtEngineFuzzTarget>("type1-tar");
  (void)add<Type1RenderFuzzTarget>("type1-render");
  (void)add<Type1RenderFtEngineFuzzTarget>("type1-render-ftengine");
  (void)add<Type1RenderFtEngineFuzzTarget>("type1-render-tar");

  (void)add<Type42FuzzTarget>("type42");
  (void)add<Type42RenderFuzzTarget>("type42-render");

  (void)add<WindowsFntFuzzTarget>("windowsfnt");
  (void)add<WindowsFntRenderFuzzTarget>("windowsfnt-render");

  (void)add<GlyphsOutlinesFuzzTarget>("glyphs-outlines");
  (void)add<GlyphsBitmapsPcfFuzzTarget>("glyphs-bitmaps-pcf");

  (void)add<GzipFuzzTarget>("gzip");
  (void)add<LzwFuzzTarget>("lzw");
  (void)add<Bzip2FuzzTarget>("bzip2");
}

bool freetype::DriverInternals::run(const std::string &type_arg, const uint8_t *data, size_t size) {
  if (type_arg == "--legacy") {
    (void)LLVMFuzzerTestOneInput(data, size);
    return true;
  }

  auto target = targets.find(type_arg);
  if (target == targets.end())
    return false;

  (void)target->second(data, size);

  return true;
}

void freetype::DriverInternals::print_error(const std::string &message) { std::cerr << message << "\n"; }

void freetype::DriverInternals::print_usage() {
  std::cerr << "\nUsage: driver TYPE FILE\n\n"
            << "Type:\n\n";

  for (auto t : usage_types)
    std::cerr << "  --" << t << "\n";

  std::cerr << "\nFile:\n\n"
            << "  The location (path) of an input file.\n\n";
}
