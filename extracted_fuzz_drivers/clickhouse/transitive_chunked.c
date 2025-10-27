/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/compression/huffman.h>

#include <aws/compression/private/huffman_testing.h>
#include <aws/testing/aws_test_harness.h>

struct aws_huffman_symbol_coder *test_get_coder(void);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  if (!size) {
    return 0;
  }

  static const size_t step_sizes[] = {1, 2, 4, 8, 16, 32, 64, 128};
  for (size_t i = 0; i < sizeof(step_sizes) / sizeof(size_t); ++i) {
    size_t step_size = step_sizes[i];

    const char *error_message = NULL;
    int result = huffman_test_transitive_chunked(test_get_coder(), (const char *)data, size, 0, step_size, &error_message);
    ASSERT_SUCCESS(result, error_message);
  }

  return 0; // Non-zero return values are reserved for future use.
}
