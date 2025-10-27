/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/encoding.h>

/* NOLINTNEXTLINE(readability-identifier-naming) */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  struct aws_allocator *allocator = aws_default_allocator();

  size_t output_size = 0;
  int result = aws_base64_compute_encoded_len(size, &output_size);
  AWS_ASSERT(result == AWS_OP_SUCCESS);

  struct aws_byte_cursor to_encode = aws_byte_cursor_from_array(data, size);

  struct aws_byte_buf encode_output;
  result = aws_byte_buf_init(&encode_output, allocator, output_size);
  AWS_ASSERT(result == AWS_OP_SUCCESS);

  result = aws_base64_encode(&to_encode, &encode_output);
  AWS_ASSERT(result == AWS_OP_SUCCESS);

  struct aws_byte_cursor to_decode = aws_byte_cursor_from_buf(&encode_output);
  result = aws_base64_compute_decoded_len(&to_decode, &output_size);
  AWS_ASSERT(result == AWS_OP_SUCCESS);
  AWS_ASSERT(output_size == size);

  struct aws_byte_buf decode_output;
  result = aws_byte_buf_init(&decode_output, allocator, output_size);
  AWS_ASSERT(result == AWS_OP_SUCCESS);

  result = aws_base64_decode(&to_decode, &decode_output);
  AWS_ASSERT(result == AWS_OP_SUCCESS);
  AWS_ASSERT(output_size == decode_output.len);
  AWS_ASSERT(memcmp(decode_output.buffer, data, size) == 0);

  aws_byte_buf_clean_up(&encode_output);
  aws_byte_buf_clean_up(&decode_output);

  return 0;
}
