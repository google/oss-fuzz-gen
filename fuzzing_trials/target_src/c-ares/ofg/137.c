#include <ares.h>
#include <stddef.h>
#include <stdint.h>

// Entrypoint for Clang's libfuzzer
int LLVMFuzzerTestOneInput_137(const uint8_t *data, size_t size) {
  // Declare ares_channel pointer
  ares_channel channel = NULL;

  // Call the function-under-test
  int result = ares_init(&channel);

  // If initialization was successful, destroy the channel
  if (result == ARES_SUCCESS && channel != NULL) {
    ares_destroy(channel);
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

    LLVMFuzzerTestOneInput_137(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
