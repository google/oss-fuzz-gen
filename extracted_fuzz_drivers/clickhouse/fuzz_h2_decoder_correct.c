/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/testing/aws_test_harness.h>

#include <aws/common/allocator.h>
#include <aws/common/byte_buf.h>
#include <aws/common/logging.h>

#include <aws/http/private/h2_decoder.h>
#include <aws/http/private/h2_frames.h>
#include <aws/http/private/hpack.h>

#include <aws/io/stream.h>

#include <inttypes.h>

static const uint32_t MAX_PAYLOAD_SIZE = 16384;

enum header_style {
  HEADER_STYLE_REQUEST,
  HEADER_STYLE_RESPONSE,
  HEADER_STYLE_TRAILER,
};

static struct aws_http_headers *s_generate_headers(struct aws_allocator *allocator, struct aws_byte_cursor *input, enum header_style header_style) {

  struct aws_http_headers *headers = aws_http_headers_new(allocator);

  /* There are pretty strict requirements about pseudo-headers, no randomness for now */
  if (header_style == HEADER_STYLE_REQUEST) {
    struct aws_http_header method = {.name = aws_http_header_method, .value = aws_http_method_get};
    aws_http_headers_add_header(headers, &method);

    struct aws_http_header scheme = {.name = aws_http_header_scheme, .value = aws_http_scheme_https};
    aws_http_headers_add_header(headers, &scheme);

    struct aws_http_header path = {.name = aws_http_header_path, .value = aws_byte_cursor_from_c_str("/")};
    aws_http_headers_add_header(headers, &path);

    struct aws_http_header authority = {
        .name = aws_http_header_authority,
        .value = aws_byte_cursor_from_c_str("example.com"),
    };
    aws_http_headers_add_header(headers, &authority);

  } else if (header_style == HEADER_STYLE_RESPONSE) {
    struct aws_http_header status = {.name = aws_http_header_status, .value = aws_byte_cursor_from_c_str("200")};
    aws_http_headers_add_header(headers, &status);
  }

  struct aws_byte_buf buf;
  aws_byte_buf_init(&buf, allocator, 1024);

  while (input->len) {
    buf.len = 0;

    struct aws_http_header header;
    AWS_ZERO_STRUCT(header);

    uint8_t type = 0;
    aws_byte_cursor_read_u8(input, &type);
    switch (type % 3) {
    case 0:
      header.compression = AWS_HTTP_HEADER_COMPRESSION_USE_CACHE;
      break;
    case 1:
      header.compression = AWS_HTTP_HEADER_COMPRESSION_NO_CACHE;
      break;
    case 2:
      header.compression = AWS_HTTP_HEADER_COMPRESSION_NO_FORWARD_CACHE;
      break;
    }

    /* Start name with "x-" so we don't violate some rule for an official header.
     * Then add some more valid characters. */
    struct aws_byte_cursor header_name_prefix = aws_byte_cursor_from_c_str("x-");
    aws_byte_buf_append(&buf, &header_name_prefix);

    uint8_t name_suffix_len = 0;
    aws_byte_cursor_read_u8(input, &name_suffix_len);
    for (size_t i = 0; i < name_suffix_len; ++i) {
      uint8_t c = 0;
      aws_byte_cursor_read_u8(input, &c);
      c = 'a' + (c % 26); /* a-z */
      aws_byte_buf_write_u8(&buf, c);
    }

    header.name = aws_byte_cursor_from_buf(&buf);

    /* Fill header.value with valid characters */
    uint8_t value_len = 0;
    aws_byte_cursor_read_u8(input, &value_len);
    for (size_t i = 0; i < value_len; ++i) {
      uint8_t c = 0;
      aws_byte_cursor_read_u8(input, &c);
      c = 'a' + (c % 26); /* a-z */
      aws_byte_buf_write_u8(&buf, c);
    }

    header.value = aws_byte_cursor_from_buf(&buf);
    aws_byte_cursor_advance(&header.value, header.name.len);

    aws_http_headers_add_header(headers, &header);
  }

  aws_byte_buf_clean_up(&buf);
  return headers;
}

static uint32_t s_generate_stream_id(struct aws_byte_cursor *input) {
  uint32_t stream_id = 0;
  aws_byte_cursor_read_be32(input, &stream_id);
  return aws_min_u32(AWS_H2_STREAM_ID_MAX, aws_max_u32(1, stream_id));
}

/* Server-initiated stream-IDs must be even */
static uint32_t s_generate_even_stream_id(struct aws_byte_cursor *input) {
  uint32_t stream_id = 0;
  aws_byte_cursor_read_be32(input, &stream_id);
  stream_id = aws_min_u32(AWS_H2_STREAM_ID_MAX, aws_max_u32(2, stream_id));

  if (stream_id % 2 != 0) {
    stream_id -= 1;
  }

  return stream_id;
}

/* Client-initiated stream-IDs must be odd */
static uint32_t s_generate_odd_stream_id(struct aws_byte_cursor *input) {
  uint32_t stream_id = 0;
  aws_byte_cursor_read_be32(input, &stream_id);
  stream_id = aws_min_u32(AWS_H2_STREAM_ID_MAX, aws_max_u32(1, stream_id));

  if (stream_id % 2 == 0) {
    stream_id += 1;
  }

  return stream_id;
}

static struct aws_h2_frame_priority_settings s_generate_priority(struct aws_byte_cursor *input) {
  struct aws_h2_frame_priority_settings priority;
  priority.stream_dependency = s_generate_stream_id(input);

  uint8_t exclusive = 0;
  aws_byte_cursor_read_u8(input, &exclusive);
  priority.stream_dependency_exclusive = (bool)exclusive;

  aws_byte_cursor_read_u8(input, &priority.weight);

  return priority;
}

AWS_EXTERN_C_BEGIN

/**
 * This test generates valid frames from the random input.
 * It feeds these frames through the encoder and ensures that they're output without error.
 * Then it feeds the encoder's output to the decoder and ensures that it does not report an error.
 * It does not currently investigate the outputs to see if they line up with they inputs,
 * it just checks for errors from the encoder & decoder.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* Setup allocator and parameters */
  struct aws_allocator *allocator = aws_mem_tracer_new(aws_default_allocator(), NULL, AWS_MEMTRACE_BYTES, 0);
  struct aws_byte_cursor input = aws_byte_cursor_from_array(data, size);

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

  /* Create the encoder */
  struct aws_h2_frame_encoder encoder;
  aws_h2_frame_encoder_init(&encoder, allocator, NULL /*logging_id*/);

  /* Create the decoder */
  uint8_t decoder_is_server = 0;
  aws_byte_cursor_read_u8(&input, &decoder_is_server);
  const struct aws_h2_decoder_vtable decoder_vtable = {0};
  struct aws_h2_decoder_params decoder_params = {
      .alloc = allocator,
      .vtable = &decoder_vtable,
      .skip_connection_preface = true,
      .is_server = decoder_is_server,
  };
  struct aws_h2_decoder *decoder = aws_h2_decoder_new(&decoder_params);

  /* Init the buffer */
  struct aws_byte_buf frame_data;
  aws_byte_buf_init(&frame_data, allocator, AWS_H2_FRAME_PREFIX_SIZE + MAX_PAYLOAD_SIZE);

  /*
   * Generate the frame to decode
   */

  uint8_t frame_type = 0;
  aws_byte_cursor_read_u8(&input, &frame_type);
  frame_type = frame_type % (AWS_H2_FRAME_TYPE_COUNT);
  if (decoder_is_server && frame_type == AWS_H2_FRAME_T_PUSH_PROMISE) {
    /* Client can't send push-promise to server */
    frame_type = AWS_H2_FRAME_T_HEADERS;
  }

  /* figure out if we should use huffman encoding */
  uint8_t huffman_choice = 0;
  aws_byte_cursor_read_u8(&input, &huffman_choice);
  aws_hpack_encoder_set_huffman_mode(&encoder.hpack, huffman_choice % 3);

  switch (frame_type) {
  case AWS_H2_FRAME_T_DATA: {
    uint32_t stream_id = s_generate_stream_id(&input);

    uint8_t flags = 0;
    aws_byte_cursor_read_u8(&input, &flags);
    bool body_ends_stream = flags & AWS_H2_FRAME_F_END_STREAM;

    uint8_t pad_length = 0;
    aws_byte_cursor_read_u8(&input, &pad_length);

    /* Allow body to exceed available space. Data encoder should just write what it can fit */
    struct aws_input_stream *body = aws_input_stream_new_from_cursor(allocator, &input);

    bool body_complete;
    bool body_stalled;
    int32_t stream_window_size_peer = AWS_H2_WINDOW_UPDATE_MAX;
    size_t connection_window_size_peer = AWS_H2_WINDOW_UPDATE_MAX;
    AWS_FATAL_ASSERT(aws_h2_encode_data_frame(&encoder, stream_id, body, (bool)body_ends_stream, pad_length, &stream_window_size_peer, &connection_window_size_peer, &frame_data, &body_complete, &body_stalled) == AWS_OP_SUCCESS);

    struct aws_stream_status body_status;
    aws_input_stream_get_status(body, &body_status);
    AWS_FATAL_ASSERT(body_complete == body_status.is_end_of_stream);
    aws_input_stream_release(body);
    break;
  }
  case AWS_H2_FRAME_T_HEADERS: {
    /* If decoder is server, headers can only arrive on client-initiated streams
     * If decoder is client, header might arrive on server-initiated or client-initiated streams */
    uint32_t stream_id = decoder_is_server ? s_generate_odd_stream_id(&input) : s_generate_stream_id(&input);

    uint8_t flags = 0;
    aws_byte_cursor_read_u8(&input, &flags);
    bool end_stream = flags & AWS_H2_FRAME_F_END_STREAM;
    bool use_priority = flags & AWS_H2_FRAME_F_PRIORITY;

    uint8_t pad_length = 0;
    aws_byte_cursor_read_u8(&input, &pad_length);

    struct aws_h2_frame_priority_settings priority = s_generate_priority(&input);
    struct aws_h2_frame_priority_settings *priority_ptr = use_priority ? &priority : NULL;

    /* Server can only receive request-style HEADERS, client can only receive response-style HEADERS.
     * But either side can receive trailer-style HEADERS */
    uint8_t is_normal_header = 0;
    aws_byte_cursor_read_u8(&input, &is_normal_header);
    enum header_style header_style;
    if (is_normal_header) {
      if (decoder_is_server) {
        header_style = HEADER_STYLE_REQUEST;
      } else {
        header_style = HEADER_STYLE_RESPONSE;
      }
    } else {
      header_style = HEADER_STYLE_TRAILER;
      end_stream = true; /* Trailer must END_STREAM */
    }

    /* generate headers last since it uses up the rest of input */
    struct aws_http_headers *headers = s_generate_headers(allocator, &input, header_style);

    struct aws_h2_frame *frame = aws_h2_frame_new_headers(allocator, stream_id, headers, end_stream, pad_length, priority_ptr);
    AWS_FATAL_ASSERT(frame);

    bool frame_complete;
    AWS_FATAL_ASSERT(aws_h2_encode_frame(&encoder, frame, &frame_data, &frame_complete) == AWS_OP_SUCCESS);
    AWS_FATAL_ASSERT(frame_complete == true);

    aws_h2_frame_destroy(frame);
    aws_http_headers_release(headers);
    break;
  }
  case AWS_H2_FRAME_T_PRIORITY: {
    uint32_t stream_id = s_generate_stream_id(&input);
    struct aws_h2_frame_priority_settings priority = s_generate_priority(&input);

    struct aws_h2_frame *frame = aws_h2_frame_new_priority(allocator, stream_id, &priority);
    AWS_FATAL_ASSERT(frame);

    bool frame_complete;
    AWS_FATAL_ASSERT(aws_h2_encode_frame(&encoder, frame, &frame_data, &frame_complete) == AWS_OP_SUCCESS);
    AWS_FATAL_ASSERT(frame_complete == true);

    aws_h2_frame_destroy(frame);
    break;
  }
  case AWS_H2_FRAME_T_RST_STREAM: {
    uint32_t stream_id = s_generate_stream_id(&input);

    uint32_t error_code = 0;
    aws_byte_cursor_read_be32(&input, &error_code);

    struct aws_h2_frame *frame = aws_h2_frame_new_rst_stream(allocator, stream_id, error_code);
    AWS_FATAL_ASSERT(frame);

    bool frame_complete;
    AWS_FATAL_ASSERT(aws_h2_encode_frame(&encoder, frame, &frame_data, &frame_complete) == AWS_OP_SUCCESS);
    AWS_FATAL_ASSERT(frame_complete == true);

    aws_h2_frame_destroy(frame);
    break;
  }
  case AWS_H2_FRAME_T_SETTINGS: {
    uint8_t flags = 0;
    aws_byte_cursor_read_u8(&input, &flags);

    bool ack = flags & AWS_H2_FRAME_F_ACK;

    size_t settings_count = 0;
    struct aws_http2_setting *settings_array = NULL;

    if (!ack) {
      settings_count = aws_min_size(input.len / 6, MAX_PAYLOAD_SIZE);
      if (settings_count > 0) {
        settings_array = aws_mem_calloc(allocator, settings_count, sizeof(struct aws_http2_setting));
        for (size_t i = 0; i < settings_count; ++i) {
          uint16_t id = 0;
          uint32_t value = 0;
          aws_byte_cursor_read_be16(&input, &id);
          aws_byte_cursor_read_be32(&input, &value);
          if (id >= AWS_HTTP2_SETTINGS_BEGIN_RANGE && id < AWS_HTTP2_SETTINGS_END_RANGE) {
            value = aws_max_u32(value, aws_h2_settings_bounds[id][0]);
            value = aws_min_u32(value, aws_h2_settings_bounds[id][1]);
          }
          settings_array[i].id = id;
          settings_array[i].value = value;
        }
      }
    }

    struct aws_h2_frame *frame = aws_h2_frame_new_settings(allocator, settings_array, settings_count, ack);
    AWS_FATAL_ASSERT(frame);

    bool frame_complete;
    AWS_FATAL_ASSERT(aws_h2_encode_frame(&encoder, frame, &frame_data, &frame_complete) == AWS_OP_SUCCESS);
    AWS_FATAL_ASSERT(frame_complete == true);

    aws_h2_frame_destroy(frame);
    aws_mem_release(allocator, settings_array);
    break;
  }
  case AWS_H2_FRAME_T_PUSH_PROMISE: {
    uint32_t stream_id = s_generate_odd_stream_id(&input);
    uint32_t promised_stream_id = s_generate_even_stream_id(&input);

    uint8_t pad_length = 0;
    aws_byte_cursor_read_u8(&input, &pad_length);

    /* generate headers last since it uses up the rest of input */
    struct aws_http_headers *headers = s_generate_headers(allocator, &input, HEADER_STYLE_REQUEST);

    struct aws_h2_frame *frame = aws_h2_frame_new_push_promise(allocator, stream_id, promised_stream_id, headers, pad_length);
    AWS_FATAL_ASSERT(frame);

    bool frame_complete;
    AWS_FATAL_ASSERT(aws_h2_encode_frame(&encoder, frame, &frame_data, &frame_complete) == AWS_OP_SUCCESS);
    AWS_FATAL_ASSERT(frame_complete == true);

    aws_h2_frame_destroy(frame);
    aws_http_headers_release(headers);
    break;
  }
  case AWS_H2_FRAME_T_PING: {
    uint8_t flags;
    aws_byte_cursor_read_u8(&input, &flags);
    bool ack = flags & AWS_H2_FRAME_F_ACK;

    uint8_t opaque_data[AWS_HTTP2_PING_DATA_SIZE] = {0};
    size_t copy_len = aws_min_size(input.len, AWS_HTTP2_PING_DATA_SIZE);
    if (copy_len > 0) {
      struct aws_byte_cursor copy = aws_byte_cursor_advance(&input, copy_len);
      memcpy(opaque_data, copy.ptr, copy.len);
    }

    struct aws_h2_frame *frame = aws_h2_frame_new_ping(allocator, ack, opaque_data);
    AWS_FATAL_ASSERT(frame);

    bool frame_complete;
    AWS_FATAL_ASSERT(aws_h2_encode_frame(&encoder, frame, &frame_data, &frame_complete) == AWS_OP_SUCCESS);
    AWS_FATAL_ASSERT(frame_complete == true);

    aws_h2_frame_destroy(frame);
    break;
  }
  case AWS_H2_FRAME_T_GOAWAY: {
    uint32_t last_stream_id = s_generate_stream_id(&input);

    uint32_t error_code = 0;
    aws_byte_cursor_read_be32(&input, &error_code);

    /* Pass debug_data that might be too large (it will get truncated if necessary) */
    struct aws_byte_cursor debug_data = aws_byte_cursor_advance(&input, input.len);

    struct aws_h2_frame *frame = aws_h2_frame_new_goaway(allocator, last_stream_id, error_code, debug_data);
    AWS_FATAL_ASSERT(frame);

    bool frame_complete;
    AWS_FATAL_ASSERT(aws_h2_encode_frame(&encoder, frame, &frame_data, &frame_complete) == AWS_OP_SUCCESS);
    AWS_FATAL_ASSERT(frame_complete == true);

    aws_h2_frame_destroy(frame);
    break;
  }
  case AWS_H2_FRAME_T_WINDOW_UPDATE: {
    /* WINDOW_UPDATE's stream-id can be zero or non-zero */
    uint32_t stream_id = 0;
    aws_byte_cursor_read_be32(&input, &stream_id);
    stream_id = aws_min_u32(stream_id, AWS_H2_STREAM_ID_MAX);

    uint32_t window_size_increment = 0;
    aws_byte_cursor_read_be32(&input, &window_size_increment);
    window_size_increment = aws_min_u32(window_size_increment, AWS_H2_WINDOW_UPDATE_MAX);

    struct aws_h2_frame *frame = aws_h2_frame_new_window_update(allocator, stream_id, window_size_increment);
    AWS_FATAL_ASSERT(frame);

    bool frame_complete;
    AWS_FATAL_ASSERT(aws_h2_encode_frame(&encoder, frame, &frame_data, &frame_complete) == AWS_OP_SUCCESS);
    AWS_FATAL_ASSERT(frame_complete == true);

    aws_h2_frame_destroy(frame);
    break;
  }
  case AWS_H2_FRAME_T_CONTINUATION:
    /* We don't directly create CONTINUATION frames (they occur when HEADERS or PUSH_PROMISE gets too big) */
    frame_type = AWS_H2_FRAME_T_UNKNOWN;
    /* fallthrough */
  case AWS_H2_FRAME_T_UNKNOWN: {
    /* #YOLO roll our own frame */
    uint32_t payload_length = aws_min_u32(input.len, MAX_PAYLOAD_SIZE - AWS_H2_FRAME_PREFIX_SIZE);

    /* Write payload length */
    aws_byte_buf_write_be24(&frame_data, payload_length);

    /* Write type */
    aws_byte_buf_write_u8(&frame_data, frame_type);

    /* Write flags */
    uint8_t flags = 0;
    aws_byte_cursor_read_u8(&input, &flags);
    aws_byte_buf_write_u8(&frame_data, flags);

    /* Write stream-id */
    uint32_t stream_id = 0;
    aws_byte_cursor_read_be32(&input, &stream_id);
    aws_byte_buf_write_be32(&frame_data, stream_id);

    /* Write payload */
    aws_byte_buf_write_from_whole_cursor(&frame_data, aws_byte_cursor_advance(&input, payload_length));
    break;
  }
  default: {
    AWS_FATAL_ASSERT(false);
  }
  }

  /* Decode whatever we got */
  AWS_FATAL_ASSERT(frame_data.len > 0);
  struct aws_byte_cursor to_decode = aws_byte_cursor_from_buf(&frame_data);
  struct aws_h2err err = aws_h2_decode(decoder, &to_decode);
  AWS_FATAL_ASSERT(aws_h2err_success(err));
  AWS_FATAL_ASSERT(to_decode.len == 0);

  /* Clean up */
  aws_byte_buf_clean_up(&frame_data);
  aws_h2_decoder_destroy(decoder);
  aws_h2_frame_encoder_clean_up(&encoder);
  aws_logger_set(NULL);
  aws_logger_clean_up(&logger);

  atexit(aws_http_library_clean_up);

  /* Check for leaks */
  AWS_FATAL_ASSERT(aws_mem_tracer_count(allocator) == 0);
  allocator = aws_mem_tracer_destroy(allocator);

  return 0;
}

AWS_EXTERN_C_END
