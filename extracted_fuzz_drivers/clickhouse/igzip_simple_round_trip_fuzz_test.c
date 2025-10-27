#include "igzip_lib.h"
#include "unaligned.h"
#include <assert.h>
#include <byteswap.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define LEVEL_BITS 2
#define HEADER_BITS 3
#define LVL_BUF_BITS 3

#define LEVEL_BIT_MASK ((1 << LEVEL_BITS) - 1)
#define HEADER_BIT_MASK ((1 << HEADER_BITS) - 1)
#define TYPE0_HDR_SIZE 5
#define TYPE0_MAX_SIZE 65535

#define MIN(x, y) (((x) > (y)) ? y : x)

const int header_size[] = {
    0,  // IGZIP_DEFLATE
    10, // IGZIP_GZIP
    0,  // IGZIP_GZIP_NO_HDR
    2,  // IGZIP_ZLIB
    0,  // IGZIP_ZLIB_NO_HDR
};

const int trailer_size[] = {
    0, // IGZIP_DEFLATE
    8, // IGZIP_GZIP
    8, // IGZIP_GZIP_NO_HDR
    4, // IGZIP_ZLIB
    4, // IGZIP_ZLIB_NO_HDR
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct inflate_state istate;
  struct isal_zstream cstate;
  uint8_t *in_data = (uint8_t *)data;
  int ret = 1;

  // Parameter default
  int level = 1;
  int lev_buf_size = ISAL_DEF_LVL1_DEFAULT;
  int wrapper_type = 0;
  size_t cmp_buf_size = size + ISAL_DEF_MAX_HDR_SIZE;

  // Parameters are set by one byte of data input
  if (size > 1) {
    uint8_t in_param = in_data[--size];
    level = MIN(in_param & LEVEL_BIT_MASK, ISAL_DEF_MAX_LEVEL);
    in_param >>= LEVEL_BITS;

    wrapper_type = (in_param & HEADER_BIT_MASK) % (IGZIP_ZLIB_NO_HDR + 1);
    in_param >>= HEADER_BITS;

    switch (level) {
    case 0:
      lev_buf_size = ISAL_DEF_LVL0_MIN + (in_param) * (ISAL_DEF_LVL0_EXTRA_LARGE / LEVEL_BIT_MASK);
      break;
    case 1:
      lev_buf_size = ISAL_DEF_LVL1_MIN + (in_param) * (ISAL_DEF_LVL1_EXTRA_LARGE / LEVEL_BIT_MASK);
      break;
#ifdef ISAL_DEF_LVL2_MIN
    case 2:
      lev_buf_size = ISAL_DEF_LVL2_MIN + (in_param) * (ISAL_DEF_LVL2_EXTRA_LARGE / LEVEL_BIT_MASK);
      break;
#endif
#ifdef ISAL_DEF_LVL3_MIN
    case 3:
      lev_buf_size = ISAL_DEF_LVL3_MIN + (in_param) * (ISAL_DEF_LVL3_EXTRA_LARGE / LEVEL_BIT_MASK);
      break;
#endif
    }
    if (0 == level)
      cmp_buf_size = 2 * size + ISAL_DEF_MAX_HDR_SIZE;
    else
      cmp_buf_size = size + 8 + (TYPE0_HDR_SIZE * (size / TYPE0_MAX_SIZE));

    cmp_buf_size += header_size[wrapper_type] + trailer_size[wrapper_type];
  }

  uint8_t *isal_cmp_buf = (uint8_t *)malloc(cmp_buf_size);
  uint8_t *isal_out_buf = (uint8_t *)malloc(size);
  uint8_t *isal_lev_buf = (uint8_t *)malloc(lev_buf_size);
  assert(NULL != isal_cmp_buf || NULL != isal_out_buf || NULL != isal_lev_buf);

  isal_deflate_init(&cstate);
  cstate.end_of_stream = 1;
  cstate.flush = NO_FLUSH;
  cstate.next_in = in_data;
  cstate.avail_in = size;
  cstate.next_out = isal_cmp_buf;
  cstate.avail_out = cmp_buf_size;
  cstate.level = level;
  cstate.level_buf = isal_lev_buf;
  cstate.level_buf_size = lev_buf_size;
  cstate.gzip_flag = wrapper_type;
  ret = isal_deflate_stateless(&cstate);

  isal_inflate_init(&istate);
  istate.next_in = isal_cmp_buf;
  istate.avail_in = cstate.total_out;
  istate.next_out = isal_out_buf;
  istate.avail_out = size;
  istate.crc_flag = wrapper_type;
  ret |= isal_inflate_stateless(&istate);
  ret |= memcmp(isal_out_buf, in_data, size);

  // Check trailer
  uint32_t crc = 0;
  int trailer_idx = cstate.total_out - trailer_size[wrapper_type];

  if (wrapper_type == IGZIP_GZIP || wrapper_type == IGZIP_GZIP_NO_HDR)
    crc = load_le_u32(&isal_cmp_buf[trailer_idx]);
  else if (wrapper_type == IGZIP_ZLIB || wrapper_type == IGZIP_ZLIB_NO_HDR)
    crc = load_be_u32(&isal_cmp_buf[trailer_idx]);

  assert(istate.crc == crc);
  free(isal_cmp_buf);
  free(isal_out_buf);
  free(isal_lev_buf);
  return ret;
}
