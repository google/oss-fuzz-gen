#include <stddef.h>
#include <stdint.h>
#include <ares.h>

extern int LLVMFuzzerTestOneInput_103(const uint8_t *data, size_t size) {
  ares_channel channel;
  struct ares_options options;
  int optmask = 0;
  int status = ares_init_options(&channel, &options, optmask);

  if (status == ARES_SUCCESS) {
    if (size >= sizeof(unsigned int)) {
      unsigned int local_ip = *(unsigned int *)data;
      ares_set_local_ip4(channel, local_ip);
    }
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

    LLVMFuzzerTestOneInput_103(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
