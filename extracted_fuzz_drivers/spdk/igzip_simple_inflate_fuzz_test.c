#include "igzip_lib.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct inflate_state state;
  uint8_t *isal_out_buf = (uint8_t *)(malloc(size * 2));
  size_t out_buf_size = 2 * size;

  isal_inflate_init(&state);
  state.next_in = (uint8_t *)data;
  state.avail_in = size;
  state.next_out = isal_out_buf;
  state.avail_out = out_buf_size;

  isal_inflate_stateless(&state);

  free(isal_out_buf);
  return 0;
}
