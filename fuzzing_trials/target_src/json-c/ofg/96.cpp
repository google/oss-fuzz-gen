#include <fuzzer/FuzzedDataProvider.h>

// Declare the function-under-test
extern "C" const char * json_util_get_last_err();

extern "C" int LLVMFuzzerTestOneInput_96(const uint8_t *data, size_t size) {
  // Since the function-under-test does not take any parameters, we directly call it.
  const char *error_message = json_util_get_last_err();

  // To ensure the function call is not optimized away, we can perform a simple operation on the result.
  if (error_message) {
    volatile char first_char = error_message[0];
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

    LLVMFuzzerTestOneInput_96(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
