// Copyright 2020 Google LLC
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

#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "fuzzing/replay/test_replayer.h"

extern "C" {
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerInitialize(int *argc, char ***argv) __attribute__((weak));
}

namespace {

constexpr size_t kMaxTestFileSize = 4 * 1024 * 1024;

} // namespace

int main(int argc, char **argv) {
  if (LLVMFuzzerInitialize) {
    LLVMFuzzerInitialize(&argc, &argv);
  }

  absl::Status overall_status = absl::OkStatus();
  fuzzing::TestReplayer replayer(&LLVMFuzzerTestOneInput, kMaxTestFileSize);
  for (int i = 1; i < argc; ++i) {
    const absl::Status status = replayer.ReplayTests(argv[i]);
    if (!status.ok()) {
      absl::FPrintF(stderr, "** Errors encountered when replaying '%s': %s\n", argv[i], status.ToString());
    }
    overall_status.Update(status);
  }
  return overall_status.ok() ? EXIT_SUCCESS : EXIT_FAILURE;
}
