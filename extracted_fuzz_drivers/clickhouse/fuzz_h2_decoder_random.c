/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/private/h2_decoder.h>

#include <aws/testing/aws_test_harness.h>

#include <aws/common/allocator.h>
#include <aws/common/logging.h>

AWS_EXTERN_C_BEGIN

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  /* Setup allocator and parameters */
  struct aws_allocator *allocator = aws_mem_tracer_new(aws_default_allocator(), NULL, AWS_MEMTRACE_BYTES, 0);
  struct aws_byte_cursor to_decode = aws_byte_cursor_from_array(data, size);

  /* Enable logging */
  struct aws_logger logger;
  struct aws_logger_standard_options log_options = {
      .level = AWS_LL_TRACE,
      .file = stdout,
  };
  aws_logger_init_standard(&logger, allocator, &log_options);
  aws_logger_set(&logger);

  /* Init HTTP (s2n init is weird, so don't do this under the tracer) */
  aws_http_library_init(aws_default_allocator());

  /* Create the decoder */
  struct aws_h2_decoder_vtable decoder_vtable = {0};
  struct aws_h2_decoder_params decoder_params = {
      .alloc = allocator,
      .vtable = &decoder_vtable,
      .skip_connection_preface = true,
  };
  struct aws_h2_decoder *decoder = aws_h2_decoder_new(&decoder_params);

  /* Decode whatever we got */
  aws_h2_decode(decoder, &to_decode);

  /* Clean up */
  aws_h2_decoder_destroy(decoder);
  aws_logger_set(NULL);
  aws_logger_clean_up(&logger);

  atexit(aws_http_library_clean_up);

  /* Check for leaks */
  ASSERT_UINT_EQUALS(0, aws_mem_tracer_count(allocator));
  allocator = aws_mem_tracer_destroy(allocator);

  return 0;
}

AWS_EXTERN_C_END
