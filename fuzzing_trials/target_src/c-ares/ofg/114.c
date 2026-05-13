#include <stddef.h>
#include <netinet/in.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_114(const unsigned char *data, size_t size) {
  struct hostent *host = NULL;
  unsigned char addrv4[4] = {0x10, 0x20, 0x30, 0x40}; // Example IPv4 address
  int family = AF_INET; // Address family
  int addrlen = sizeof(addrv4);

  // Call the function-under-test
  ares_parse_ptr_reply(data, (int)size, addrv4, addrlen, family, &host);

  // Free the allocated hostent structure if it was allocated
  if (host) {
    ares_free_hostent(host);
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

    LLVMFuzzerTestOneInput_114(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
