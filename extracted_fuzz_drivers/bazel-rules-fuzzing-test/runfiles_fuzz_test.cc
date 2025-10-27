// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// A fuzz target that exits if it doesn't find a declared runfile.

#include <cstddef>
#include <cstdint>

#include <fstream>
#include <iostream>
#include <string>

#include "tools/cpp/runfiles/runfiles.h"

using ::bazel::tools::cpp::runfiles::Runfiles;

namespace {
Runfiles *runfiles = nullptr;
}

extern "C" void LLVMFuzzerInitialize(int *argc, char ***argv) {
  std::string error;
  runfiles = Runfiles::Create((*argv)[0], &error);
  if (runfiles == nullptr) {
    std::cerr << error;
    abort();
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::string path = runfiles->Rlocation("rules_fuzzing/examples/corpus_0.txt");
  if (path.empty())
    abort();
  std::ifstream in(path);
  if (!in.good())
    abort();
  return 0;
}
