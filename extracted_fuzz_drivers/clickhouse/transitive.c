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

  const char *error_message = NULL;
  int result = huffman_test_transitive(test_get_coder(), (const char *)data, size, 0, &error_message);
  ASSERT_SUCCESS(result, error_message);

  return 0; // Non-zero return values are reserved for future use.
}
