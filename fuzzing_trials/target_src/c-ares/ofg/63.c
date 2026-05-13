#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ares.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>

int LLVMFuzzerTestOneInput_63(const uint8_t *data, size_t size) {
  if (size == 0) {
    return 0;
  }

  // Initialize ares library
  ares_library_init(ARES_LIB_INIT_ALL);

  // Create a channel
  ares_channel channel;
  if (ares_init(&channel) != ARES_SUCCESS) {
    return 0;
  }

  // Allocate memory for the hostname and ensure it's null-terminated
  char *name = (char *)malloc(size + 1);
  if (!name) {
    ares_destroy(channel);
    return 0;
  }
  memcpy(name, data, size);
  name[size] = '\0';

  // Set a valid family value
  int family = AF_INET; // You can also try AF_INET6 for IPv6

  // Prepare the hostent structure
  struct hostent *host = NULL;

  // Call the function-under-test
  ares_gethostbyname(channel, name, family, NULL, NULL);

  // Free resources
  if (host) {
    ares_free_hostent(host);
  }
  free(name);
  ares_destroy(channel);
  ares_library_cleanup();

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

    LLVMFuzzerTestOneInput_63(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
