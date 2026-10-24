#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_69(const uint8_t *data, size_t size) {
  struct ares_txt_reply *txt_out = NULL;

  /* Call the function-under-test */
  ares_parse_txt_reply(data, (int)size, &txt_out);

  /* Free the allocated memory if any */
  if (txt_out) {
    ares_free_data(txt_out);
  }

  return 0;
}