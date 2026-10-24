#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
  /* Ensure the data size is sufficient for an IPv6 address (16 bytes) */
  if (size < 16) {
    return 0;
  }

  // Initialize the ares channel
  ares_channel channel;
  int status = ares_init(&channel);
  if (status != ARES_SUCCESS) {
    return 0;
  }

  // Set the local IPv6 address
  ares_set_local_ip6(channel, data);

  // Clean up the ares channel
  ares_destroy(channel);

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

    LLVMFuzzerTestOneInput_32(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
