/*******************************************************************************
 * Copyright (C) 2022 Intel Corporation
 *
 * SPDX-License-Identifier: MIT
 ******************************************************************************/

#include "filter_op_fuzz_test.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) { return scan_test_case(Data, Size, qpl_p_parquet_rle); }
