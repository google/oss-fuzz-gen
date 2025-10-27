// template.cpp
//
//   Template for fuzzer executables that depends on two defines:
//     - `FUZZ_TARGET_HEADER_PATH':
//         The header path within the `targets' folder.
//     - `FUZZ_TARGET_CLASS_NAME':
//         The class name of the target.
//
// Copyright 2018-2019 by
// Armin Hasitzka, David Turner, Robert Wilhelm, and Werner Lemberg.
//
// This file is part of the FreeType project, and may only be used,
// modified, and distributed under the terms of the FreeType project
// license, LICENSE.TXT.  By continuing to use, modify, or distribute
// this file you indicate that you have read the license and
// understand and accept it fully.

#include FUZZ_TARGET_HEADER_PATH

namespace {

FUZZ_TARGET_CLASS_NAME target;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  (void)target.run(data, size);
  return 0;
}
} // namespace
