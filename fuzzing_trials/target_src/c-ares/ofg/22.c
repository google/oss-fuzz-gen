#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <ares.h>

static void nameinfo_callback(void *arg, int status, int timeouts, char *node, char *service) {
  (void)arg; // Suppress unused parameter warning
  (void)status; // Suppress unused parameter warning
  (void)timeouts; // Suppress unused parameter warning
  (void)node; // Suppress unused parameter warning
  (void)service; // Suppress unused parameter warning
}

int LLVMFuzzerTestOneInput_22(const uint8_t *data, size_t size) {
  ares_channel channel;
  struct sockaddr_in sa;
  ares_socklen_t salen = sizeof(sa);
  int flags_int = 0;
  void *arg = NULL;

  // Initialize the sockaddr_in structure
  sa.sin_family = AF_INET;
  sa.sin_port = htons(80); // Arbitrary port number
  if (size >= sizeof(sa.sin_addr.s_addr)) {
    memcpy(&sa.sin_addr.s_addr, data, sizeof(sa.sin_addr.s_addr));
  } else {
    sa.sin_addr.s_addr = INADDR_ANY;
  }

  // Initialize ares library and create a channel
  if (ares_library_init(ARES_LIB_INIT_ALL) == ARES_SUCCESS) {
    if (ares_init(&channel) == ARES_SUCCESS) {
      // Call the function-under-test
      ares_getnameinfo(channel, (struct sockaddr *)&sa, salen, flags_int, nameinfo_callback, arg);

      // Cleanup
      ares_destroy(channel);
    }
    ares_library_cleanup();
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

    LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
