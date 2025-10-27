/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/auth/private/aws_profile.h>

#include <aws/common/byte_buf.h>

#include <assert.h>

/* NOLINTNEXTLINE(readability-identifier-naming) */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  struct aws_allocator *allocator = aws_default_allocator();

  struct aws_byte_buf buffer;
  buffer.allocator = NULL;
  buffer.buffer = (uint8_t *)data;
  buffer.capacity = size;
  buffer.len = size;

  struct aws_profile_collection *profile_set = aws_profile_collection_new_from_buffer(allocator, &buffer, AWS_PST_CREDENTIALS);
  aws_profile_collection_destroy(profile_set);

  return 0;
}
