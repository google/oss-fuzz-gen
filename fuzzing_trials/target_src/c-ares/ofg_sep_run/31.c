#include <stddef.h>
#include <stdlib.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_31(const unsigned char *data, size_t size) {
  struct ares_txt_ext *txt_out = NULL;

  /* Call the function under test */
  ares_parse_txt_reply_ext(data, (int)size, &txt_out);

  /* Free the allocated memory if necessary */
  if (txt_out) {
    ares_free_data(txt_out);
  }

  return 0;
}