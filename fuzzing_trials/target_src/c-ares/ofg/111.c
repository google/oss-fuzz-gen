#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "ares.h"

int LLVMFuzzerTestOneInput_111(const unsigned char *data, size_t size) {
  struct ares_txt_ext *txt_out = NULL;

  /* Call the function-under-test */
  ares_parse_txt_reply_ext(data, (int)size, &txt_out);

  /* Free the allocated memory if any */
  if (txt_out) {
    ares_free_data(txt_out);
  }

  return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_111(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
