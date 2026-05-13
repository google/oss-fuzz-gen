#include <string.h>
#include <sys/stat.h>
#include <stddef.h>
#include "ares.h"
#include <sys/socket.h> // For AF_INET
#include <netdb.h>      // For struct hostent

static void dummy_callback(void *arg, int status, int timeouts, struct hostent *host) {
  (void)arg;     // Suppress unused parameter warning
  (void)status;  // Suppress unused parameter warning
  (void)timeouts; // Suppress unused parameter warning
  (void)host;    // Suppress unused parameter warning
}

int LLVMFuzzerTestOneInput_50(const unsigned char *data, size_t size) {
  ares_channel channel;
  struct ares_options options;
  int optmask = 0;
  int status = ares_init_options(&channel, &options, optmask);

  if (status != ARES_SUCCESS) {
    return 0;
  }

  // Define address and family
  const void *addr = data;
  int addrlen = (int)size;
  int family = AF_INET; // Use AF_INET as a default family

  // Call the function-under-test
  ares_gethostbyaddr(channel, addr, addrlen, family, dummy_callback, NULL);

  // Cleanup
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

    LLVMFuzzerTestOneInput_50(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
