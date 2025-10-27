/*******************************************************************************
 * Copyright (C) 2022 Intel Corporation
 *
 * SPDX-License-Identifier: MIT
 ******************************************************************************/

#include "deflate_canned_dict_fuzz_test.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) { return deflate_canned_dict_fuzz(Data, Size, qpl_default_level); }
