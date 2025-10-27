// Copyright 2017 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
#include "my_api.h"

#include <stdlib.h>
#include <string>

// Simple fuzz target for DoStuff().
// See http://libfuzzer.info for details.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::string str(reinterpret_cast<const char *>(data), size);
  DoStuff(str); // Disregard the output.
  if (data[0] == 'a') {
    int *x = (int *)malloc(4);
    free(x);
    return x[0];
  }
}
