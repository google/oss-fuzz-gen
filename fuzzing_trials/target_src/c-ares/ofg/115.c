#include <stddef.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_115(const unsigned char *data, size_t size) {
  /* Call the function-under-test */
  ares_bool_t result = ares_threadsafety();

  /* Use the result in some way to avoid compiler optimizations removing the call */
  if (result) {
    /* Do something if thread safety is enabled */
  } else {
    /* Do something if thread safety is not enabled */
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

    LLVMFuzzerTestOneInput_115(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
