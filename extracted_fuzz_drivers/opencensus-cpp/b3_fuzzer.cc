// Copyright 2019, OpenCensus Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "absl/strings/string_view.h"
#include "opencensus/trace/propagation/b3.h"

using ::opencensus::trace::propagation::FromB3Headers;

static constexpr char valid_trace_id[] = "463ac35c9f6413ad48485a3953bb612";
static constexpr char valid_span_id[] = "0020000000000001";
static constexpr char valid_sampled[] = "1";
static constexpr char valid_flags[] = "";

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  absl::string_view input(reinterpret_cast<const char *>(Data), Size);
  FromB3Headers(input, input, input, input);
  FromB3Headers(input, valid_span_id, valid_sampled, valid_flags);
  FromB3Headers(valid_trace_id, input, valid_sampled, valid_flags);
  FromB3Headers(valid_trace_id, valid_span_id, input, valid_flags);
  FromB3Headers(valid_trace_id, valid_span_id, valid_sampled, input);
  return 0;
}
