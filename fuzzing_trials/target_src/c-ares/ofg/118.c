#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>
#include <sys/socket.h> // For AF_INET and SOCK_STREAM

// Callback function for ares_getaddrinfo
static void ares_getaddrinfo_callback(void *arg, int status, int timeouts, struct ares_addrinfo *res) {
  // Handle the result of ares_getaddrinfo
  (void)arg; // Unused parameter
  (void)status; // Unused parameter
  (void)timeouts; // Unused parameter
  if (res) {
    ares_freeaddrinfo(res);
  }
}

int LLVMFuzzerTestOneInput_118(const unsigned char *data, size_t size) {
  ares_channel channel;
  const char *name = "example.com";
  const char *service = "http";
  struct ares_addrinfo_hints hints;
  void *arg = NULL;

  // Initialize the ares library
  if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
    return 0;
  }

  // Initialize the channel
  if (ares_init(&channel) != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  // Set hints with some default values
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  // Use the input data to modify the name or service for fuzzing
  if (size > 0) {
    name = (const char *)data;
  }

  // Call the function-under-test
  ares_getaddrinfo(channel, name, service, &hints, ares_getaddrinfo_callback, arg);

  // Clean up
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

    LLVMFuzzerTestOneInput_118(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
