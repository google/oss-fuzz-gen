#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "ares.h"

int LLVMFuzzerTestOneInput_108(const uint8_t *data, size_t size) {
  /* Ensure the data size is non-zero to create a valid string */
  if (size == 0) {
    return 0;
  }

  /* Allocate memory for the string and copy the data into it */
  void *str = malloc(size + 1);
  if (str == NULL) {
    return 0;
  }
  
  memcpy(str, data, size);
  ((char*)str)[size] = '\0'; /* Null-terminate the string */

  /* Call the function-under-test */
  ares_free_string(str);

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

    LLVMFuzzerTestOneInput_108(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
