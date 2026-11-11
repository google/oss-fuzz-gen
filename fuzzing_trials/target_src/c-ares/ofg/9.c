#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "ares.h"

int LLVMFuzzerTestOneInput_9(const unsigned char *data, size_t size) {
  if (size < 2) {
    return 0; // Not enough data to proceed
  }

  // Split the input data into two parts: encoded and abuf
  size_t half_size = size / 2;
  const unsigned char *encoded = data;
  const unsigned char *abuf = data + half_size;
  int alen = (int)(size - half_size);

  char *s = NULL;
  long enclen = 0;

  // Call the function-under-test
  ares_expand_name(encoded, abuf, alen, &s, &enclen);

  // Free the allocated memory if any
  if (s) {
    ares_free_string(s);
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

    LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
