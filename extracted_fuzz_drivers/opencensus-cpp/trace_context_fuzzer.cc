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
#include "opencensus/trace/propagation/trace_context.h"
#include "opencensus/trace/span_context.h"

using ::opencensus::trace::SpanContext;
using ::opencensus::trace::propagation::FromTraceParentHeader;
using ::opencensus::trace::propagation::ToTraceParentHeader;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  absl::string_view header(reinterpret_cast<const char *>(Data), Size);
  SpanContext ctx = FromTraceParentHeader(header);
  if (ctx.IsValid()) {
    ToTraceParentHeader(ctx);
  }
  return 0;
}
