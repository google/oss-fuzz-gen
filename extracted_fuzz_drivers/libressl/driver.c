/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */
#include "fuzzer.h"
#include <openssl/opensslconf.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len);

int LLVMFuzzerInitialize(int *argc, char ***argv) { return FuzzerInitialize(argc, argv); }

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) { return FuzzerTestOneInput(buf, len); }
