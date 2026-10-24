#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>
#include <sys/socket.h> // For AF_INET and AF_INET6

// Dummy callback function for ares_gethostbyname
static void host_callback(void *arg, int status, int timeouts, struct hostent *host) {
  (void)arg; // Suppress unused parameter warning
  (void)status; // Suppress unused parameter warning
  (void)timeouts; // Suppress unused parameter warning
  (void)host; // Suppress unused parameter warning
}

int LLVMFuzzerTestOneInput_57(const unsigned char *data, size_t size) {
  if (size == 0) {
    return 0;
  }

  // Initialize ares library
  ares_library_init(ARES_LIB_INIT_ALL);

  ares_channel channel;
  struct ares_options options;
  int optmask = 0;

  // Initialize ares channel
  if (ares_init_options(&channel, &options, optmask) != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  // Ensure null-terminated string for the name
  char *name = (char *)malloc(size + 1);
  if (!name) {
    ares_destroy(channel);
    ares_library_cleanup();
    return 0;
  }
  memcpy(name, data, size);
  name[size] = '\0';

  // Choose a family, AF_INET or AF_INET6
  int family = (size % 2 == 0) ? AF_INET : AF_INET6;

  // Call the function under test
  ares_gethostbyname(channel, name, family, host_callback, NULL);

  // Cleanup
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

    LLVMFuzzerTestOneInput_57(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
