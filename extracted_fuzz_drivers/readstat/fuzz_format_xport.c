#include <stdlib.h>

#include "../readstat.h"
#include "../test/test_buffer.h"
#include "../test/test_buffer_io.h"
#include "../test/test_types.h"

#include "fuzz_format.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  rt_buffer_t buffer = {.bytes = (char *)Data, .size = Size, .used = Size};
  rt_buffer_ctx_t buffer_ctx = {.buffer = &buffer};

  readstat_parser_t *parser = fuzzer_parser_init(Data, Size);
  readstat_set_io_ctx(parser, &buffer_ctx);

  readstat_parse_xport(parser, NULL, NULL);
  readstat_parser_free(parser);
  return 0;
}
