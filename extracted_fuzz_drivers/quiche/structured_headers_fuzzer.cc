// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "absl/strings/string_view.h"
#include "quiche/common/structured_headers.h"

namespace quiche {
namespace structured_headers {

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  absl::string_view input(reinterpret_cast<const char *>(data), size);
  ParseItem(input);
  ParseListOfLists(input);
  ParseList(input);
  ParseDictionary(input);
  ParseParameterisedList(input);
  return 0;
}

} // namespace structured_headers
} // namespace quiche
