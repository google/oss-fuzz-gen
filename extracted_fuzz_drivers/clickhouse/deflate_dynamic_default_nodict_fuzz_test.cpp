/*******************************************************************************
 * Copyright (C) 2022 Intel Corporation
 *
 * SPDX-License-Identifier: MIT
 ******************************************************************************/

#include "deflate_nodict_fuzz_test.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) { return deflate_nodict_fuzz(Data, Size, QPL_FLAG_DYNAMIC_HUFFMAN, qpl_default_level); }
