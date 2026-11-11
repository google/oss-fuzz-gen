#include <stddef.h>
#include <netinet/in.h>
#include "ares.h"

int LLVMFuzzerTestOneInput_113(const unsigned char *data, size_t size) {
  // Ensure the input size is sufficient for the function parameters
  if (size < sizeof(struct in_addr)) {
    return 0;
  }

  struct hostent *host = NULL;
  struct in_addr addr;
  addr.s_addr = *(const uint32_t *)data; // Use the first 4 bytes for the IPv4 address
  int family = AF_INET; // Use IPv4 family
  int addrlen = sizeof(struct in_addr);

  // Call the function-under-test
  ares_parse_ptr_reply(data, (int)size, &addr, addrlen, family, &host);

  // Free the hostent structure if it was allocated
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

    LLVMFuzzerTestOneInput_113(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
