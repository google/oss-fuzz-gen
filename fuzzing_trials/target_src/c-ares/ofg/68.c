#include <ares.h>
#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_68(const uint8_t *data, size_t size) {
  ares_channel source_channel = NULL;
  ares_channel destination_channel = NULL;
  struct ares_options options;
  int optmask = 0;

  /* Initialize the source channel with some options */
  if (ares_init_options(&source_channel, &options, optmask) != ARES_SUCCESS) {
    return 0;
  }

  /* Call the function-under-test */
  ares_dup(&destination_channel, source_channel);

  /* Cleanup */
  if (source_channel) {
    ares_destroy(source_channel);
  }
  if (destination_channel) {
    ares_destroy(destination_channel);
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

    LLVMFuzzerTestOneInput_68(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
