#include "igzip_lib.h"
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct inflate_state state;
  z_stream zstate;
  size_t out_buf_size = 2 * size;
  int zret, iret;
  char z_msg_invalid_code_set[] = "invalid code lengths set";
  char z_msg_invalid_dist_set[] = "invalid distances set";
  char z_msg_invalid_lit_len_set[] = "invalid literal/lengths set";

  uint8_t *isal_out_buf = (uint8_t *)malloc(size * 2);
  uint8_t *zlib_out_buf = (uint8_t *)malloc(size * 2);

  assert(NULL != isal_out_buf && NULL != zlib_out_buf);

  /* Inflate data with isal_inflate */
  memset(&state, 0xff, sizeof(struct inflate_state));

  isal_inflate_init(&state);
  state.next_in = (uint8_t *)data;
  state.avail_in = size;
  state.next_out = isal_out_buf;
  state.avail_out = out_buf_size;

  iret = isal_inflate_stateless(&state);

  /* Inflate data with zlib */
  zstate.zalloc = Z_NULL;
  zstate.zfree = Z_NULL;
  zstate.opaque = Z_NULL;
  zstate.avail_in = size;
  zstate.next_in = (Bytef *)data;
  zstate.avail_out = out_buf_size;
  zstate.next_out = zlib_out_buf;
  inflateInit2(&zstate, -15);

  zret = inflate(&zstate, Z_FINISH);

  if (zret == Z_STREAM_END) {
    /* If zlib finished, assert isal finished with the same answer */
    assert(state.block_state == ISAL_BLOCK_FINISH);
    assert(zstate.total_out == state.total_out);
    assert(memcmp(isal_out_buf, zlib_out_buf, state.total_out) == 0);
  } else if (zret < 0) {
    if (zret != Z_BUF_ERROR)
      /* If zlib errors, assert isal errors, excluding a few
       * cases where zlib is overzealous and when zlib notices
       * an error faster than isal */
      assert(iret < 0 || strcmp(zstate.msg, z_msg_invalid_code_set) == 0 || strcmp(zstate.msg, z_msg_invalid_dist_set) == 0 || strcmp(zstate.msg, z_msg_invalid_lit_len_set) == 0 || (iret == ISAL_END_INPUT && zstate.avail_in < 3));

  } else
    /* If zlib did not finish or error, assert isal did not finish
     *  or that isal found an invalid header since isal notices the
     *  error faster than zlib */
    assert(iret > 0 || iret == ISAL_INVALID_BLOCK);

  inflateEnd(&zstate);
  free(isal_out_buf);
  free(zlib_out_buf);
  return 0;
}
