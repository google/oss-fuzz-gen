/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2017 - 2022, Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include <assert.h>
#include <curl/curl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "fuzz_bufq.h"
#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
#include "bufq.h"
}

/**
 * Allocate template buffer.  This buffer is precomputed for performance and
 * used as a cyclic pattern when reading and writing. It can be useful to
 * detect unexpected data shifting or corruption. The buffer is marked
 * read-only so it cannot be written by mistake.
 */
static unsigned char *allocate_template_buffer(void) {
  size_t sz = FUZZ_MAX_RW_SIZE + 256;
  unsigned char *buf = (unsigned char *)mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
  assert(buf != (unsigned char *)-1);

  /* Fill in with a cyclic pattern of 0, 1, ..., 255, 0, ... */
  unsigned char next_byte = 0;
  for (size_t i = 0; i < sz; i++) {
    buf[i] = next_byte++;
  }

  int err = mprotect(buf, sz, PROT_READ);
  assert(err == 0);
  return buf;
}

/*
 * Compute a pointer to a read-only buffer with our pattern, knowing that the
 * first byte to appear is next_byte.
 */
static unsigned char *compute_buffer(unsigned char next_byte, unsigned char *buf) { return buf + next_byte; }

struct writer_cb_ctx {
  bool verbose;
  unsigned char *template_buf;
  ssize_t read_len;
  unsigned char next_byte_read;
};

/**
 * Consume and verify up to read_len from a BUFQ via callback for Curl_bufq_pass.
 */
ssize_t bufq_writer_cb(void *writer_ctx, const unsigned char *buf, size_t len, CURLcode *err) {
  struct writer_cb_ctx *ctx = (struct writer_cb_ctx *)writer_ctx;

  if (ctx->read_len <= 0) {
    *err = CURLE_AGAIN;
    return -1;
  }

  FV_PRINTF(ctx->verbose, "Writer CB: %zu space available, %zu pending\n", len, ctx->read_len);

  size_t sz = len > ctx->read_len ? ctx->read_len : len;

  unsigned char *compare = compute_buffer(ctx->next_byte_read, ctx->template_buf);
  assert(memcmp(buf, compare, sz) == 0);
  ctx->next_byte_read += sz;
  ctx->read_len -= sz;

  return sz;
}

struct reader_cb_ctx {
  bool verbose;
  unsigned char *template_buf;
  ssize_t write_len;
  unsigned char next_byte_write;
};

/**
 * Write up to write_len to a BUFQ via callback for Curl_bufq_slurp/sipn.
 */
static ssize_t bufq_reader_cb(void *reader_ctx, unsigned char *buf, size_t len, CURLcode *err) {
  struct reader_cb_ctx *ctx = (struct reader_cb_ctx *)reader_ctx;

  if (ctx->write_len <= 0) {
    *err = CURLE_AGAIN;
    return -1;
  }

  FV_PRINTF(ctx->verbose, "Reader CB: %zu space available, %zu pending\n", len, ctx->write_len);

  size_t sz = len > ctx->write_len ? ctx->write_len : len;

  unsigned char *compare = compute_buffer(ctx->next_byte_write, ctx->template_buf);
  memcpy(buf, compare, sz);
  ctx->next_byte_write += sz;
  ctx->write_len -= sz;

  return sz;
}

/**
 * Function for handling the operations
 */
int fuzz_handle_bufq(FuzzedDataProvider *fuzz) {
  static bool verbose = (getenv("FUZZ_VERBOSE") != NULL);
  static unsigned char *template_buf = allocate_template_buffer();

  struct bufq q;
  struct bufc_pool pool;

  /* Prepare basic configuration values */
  int max_chunks = fuzz->ConsumeIntegralInRange(1, FUZZ_MAX_CHUNKS_QTY);
  int chunk_size = fuzz->ConsumeIntegralInRange(1, FUZZ_MAX_CHUNK_SIZE);
  bool use_pool = fuzz->ConsumeBool();
  bool no_spare = fuzz->ConsumeBool();
  int max_spare = fuzz->ConsumeIntegralInRange(1, FUZZ_MAX_MAX_SPARE);

  FV_PRINTF(verbose, "Begin fuzzing!\n");

  if (use_pool) {
    FV_PRINTF(verbose, "Using pool init\n");
    Curl_bufcp_init(&pool, chunk_size, max_spare);
    Curl_bufq_initp(&q, &pool, max_chunks, no_spare ? BUFQ_OPT_NO_SPARES : BUFQ_OPT_NONE);
  } else {
    FV_PRINTF(verbose, "Using normal init\n");
    Curl_bufq_init(&q, chunk_size, max_chunks);
  }

  ssize_t buffer_bytes = 0;
  unsigned char next_byte_read = 0;
  unsigned char next_byte_write = 0;
  while (fuzz->remaining_bytes() > 0) {
    CURLcode err = CURLE_OK;
    uint32_t op_type = fuzz->ConsumeIntegralInRange(0, OP_TYPE_MAX);

    assert(Curl_bufq_is_empty(&q) == !buffer_bytes);
    assert(Curl_bufq_len(&q) == buffer_bytes);

    switch (op_type) {
    case OP_TYPE_RESET: {
      FV_PRINTF(verbose, "OP: reset\n");
      Curl_bufq_reset(&q);
      buffer_bytes = 0;
      next_byte_read = next_byte_write;
      break;
    }

    case OP_TYPE_PEEK: {
      FV_PRINTF(verbose, "OP: peek\n");
      const unsigned char *pbuf;
      size_t plen;
      bool avail = Curl_bufq_peek(&q, &pbuf, &plen);
      if (avail) {
        unsigned char *compare = compute_buffer(next_byte_read, template_buf);
        assert(memcmp(pbuf, compare, plen) == 0);
      } else {
        FV_PRINTF(verbose, "OP: peek, error\n");
      }
      break;
    }

    case OP_TYPE_PEEK_AT: {
      size_t op_size = fuzz->ConsumeIntegralInRange(0, FUZZ_MAX_RW_SIZE);
      FV_PRINTF(verbose, "OP: peek at %zu\n", op_size);
      const unsigned char *pbuf;
      size_t plen;
      bool avail = Curl_bufq_peek_at(&q, op_size, &pbuf, &plen);
      if (avail) {
        unsigned char *compare = compute_buffer(next_byte_read + op_size, template_buf);
        assert(memcmp(pbuf, compare, plen) == 0);
      } else {
        FV_PRINTF(verbose, "OP: peek at, error\n");
      }
      break;
    }

    case OP_TYPE_READ: {
      size_t op_size = fuzz->ConsumeIntegralInRange(0, FUZZ_MAX_RW_SIZE);
      FV_PRINTF(verbose, "OP: read, size %zu\n", op_size);
      unsigned char *buf = (unsigned char *)malloc(op_size * sizeof(*buf));
      ssize_t read = Curl_bufq_read(&q, buf, op_size, &err);
      if (read != -1) {
        FV_PRINTF(verbose, "OP: read, success, read %zd, expect begins with %x\n", read, next_byte_read);
        buffer_bytes -= read;
        assert(buffer_bytes >= 0);
        unsigned char *compare = compute_buffer(next_byte_read, template_buf);
        next_byte_read += read;
        assert(memcmp(buf, compare, read) == 0);
      } else {
        FV_PRINTF(verbose, "OP: read, error\n");
      }
      free(buf);
      break;
    }

    case OP_TYPE_SLURP: {
      ssize_t op_size = fuzz->ConsumeIntegralInRange(0, FUZZ_MAX_RW_SIZE);
      FV_PRINTF(verbose, "OP: slurp, size %zd\n", op_size);
      struct reader_cb_ctx ctx = {.verbose = verbose, .template_buf = template_buf, .write_len = op_size, .next_byte_write = next_byte_write};
      ssize_t write = Curl_bufq_slurp(&q, bufq_reader_cb, &ctx, &err);
      if (write != -1) {
        FV_PRINTF(verbose, "OP: slurp, success, wrote %zd, expect begins with %x\n", write, ctx.next_byte_write);
        buffer_bytes += write;
      } else {
        FV_PRINTF(verbose, "OP: slurp, error\n");
        /* in case of -1, it may still have wrote something, adjust for that */
        buffer_bytes += (op_size - ctx.write_len);
      }
      assert(buffer_bytes <= chunk_size * max_chunks);
      next_byte_write = ctx.next_byte_write;
      break;
    }

    case OP_TYPE_SIPN: {
      ssize_t op_size = fuzz->ConsumeIntegralInRange(0, FUZZ_MAX_RW_SIZE);
      FV_PRINTF(verbose, "OP: sipn, size %zd\n", op_size);
      struct reader_cb_ctx ctx = {.verbose = verbose, .template_buf = template_buf, .write_len = op_size, .next_byte_write = next_byte_write};
      ssize_t write = Curl_bufq_sipn(&q, op_size, bufq_reader_cb, &ctx, &err);
      if (write != -1) {
        FV_PRINTF(verbose, "OP: sipn, success, wrote %zd, expect begins with %x\n", write, ctx.next_byte_write);
        buffer_bytes += write;
        assert(buffer_bytes <= chunk_size * max_chunks);
        next_byte_write = ctx.next_byte_write;
      } else {
        FV_PRINTF(verbose, "OP: sipn, error\n");
      }
      break;
    }

    case OP_TYPE_PASS: {
      ssize_t op_size = fuzz->ConsumeIntegralInRange(0, FUZZ_MAX_RW_SIZE);
      FV_PRINTF(verbose, "OP: pass, size %zd\n", op_size);
      struct writer_cb_ctx ctx = {.verbose = verbose, .template_buf = template_buf, .read_len = op_size, .next_byte_read = next_byte_read};
      ssize_t read = Curl_bufq_pass(&q, bufq_writer_cb, &ctx, &err);
      if (read != -1) {
        FV_PRINTF(verbose, "OP: pass, success, read %zd, expect begins with %x\n", read, ctx.next_byte_read);
        buffer_bytes -= read;
      } else {
        FV_PRINTF(verbose, "OP: pass, error\n");
        /* in case of -1, it may still have read something, adjust for that */
        buffer_bytes -= (op_size - ctx.read_len);
      }
      assert(buffer_bytes >= 0);
      next_byte_read = ctx.next_byte_read;
      break;
    }

    case OP_TYPE_SKIP: {
      size_t op_size = fuzz->ConsumeIntegralInRange(0, FUZZ_MAX_RW_SIZE);
      FV_PRINTF(verbose, "OP: skip, size %zu\n", op_size);
      Curl_bufq_skip(&q, op_size);
      ssize_t old_buffer_bytes = buffer_bytes;
      buffer_bytes = old_buffer_bytes > op_size ? old_buffer_bytes - op_size : 0;
      next_byte_read += old_buffer_bytes > op_size ? op_size : old_buffer_bytes;
      break;
    }

    case OP_TYPE_WRITE: {
      size_t op_size = fuzz->ConsumeIntegralInRange(0, FUZZ_MAX_RW_SIZE);
      FV_PRINTF(verbose, "OP: write, size %zu, begins with %x\n", op_size, next_byte_write);
      unsigned char *buf = compute_buffer(next_byte_write, template_buf);
      ssize_t written = Curl_bufq_write(&q, buf, op_size, &err);
      if (written != -1) {
        FV_PRINTF(verbose, "OP: write, success, written %zd\n", written);
        next_byte_write += written;
        buffer_bytes += written;
        assert(buffer_bytes <= chunk_size * max_chunks);
      } else {
        FV_PRINTF(verbose, "OP: write, error\n");
      }
      break;
    }

    default: {
      /* Should never happen */
      assert(false);
    }
    }
  }

  Curl_bufq_free(&q);
  if (use_pool) {
    Curl_bufcp_free(&pool);
  }

  return 0;
}

/**
 * Fuzzing entry point. This function is passed a buffer containing a test
 * case.  This test case should drive the cURL API into making a series of
 * BUFQ operations.
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);

  /* Ignore SIGPIPE errors. We'll handle the errors ourselves. */
  signal(SIGPIPE, SIG_IGN);

  /* Run the operations */
  fuzz_handle_bufq(&fuzzed_data);

  /* This function must always return 0. Non-zero codes are reserved. */
  return 0;
}
