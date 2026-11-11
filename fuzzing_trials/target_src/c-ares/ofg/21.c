#include <stddef.h>
#include <string.h>  // Include for memcpy and memset
#include <arpa/inet.h>
#include <ares.h>
#include <sys/socket.h>  // Include for struct sockaddr

// Declare static as it's not used outside this translation unit
static void nameinfo_callback(void *arg, int status, int timeouts, char *node, char *service) {
  // Callback function for ares_getnameinfo, can be used to handle results
  (void)arg;      // Mark unused parameters to avoid warnings
  (void)status;
  (void)timeouts;
  (void)node;
  (void)service;
}

// Declare static as it's not used outside this translation unit
int LLVMFuzzerTestOneInput_21(const unsigned char *data, size_t size) {
  ares_channel channel;  // Corrected from ares_channel_t to ares_channel
  struct ares_options options;
  int optmask = 0;
  int status = ares_init_options(&channel, &options, optmask);

  if (status != ARES_SUCCESS) {
    return 0;
  }

  struct sockaddr_in sa;
  sa.sin_family = AF_INET;
  sa.sin_port = htons(80);
  if (size >= sizeof(sa.sin_addr)) {
    memcpy(&sa.sin_addr, data, sizeof(sa.sin_addr));
  } else {
    memset(&sa.sin_addr, 0, sizeof(sa.sin_addr));
  }

  ares_socklen_t salen = sizeof(sa);
  int flags_int = 0;
  void *arg = NULL;

  ares_getnameinfo(channel, (const struct sockaddr *)&sa, salen, flags_int, nameinfo_callback, arg);

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

    LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
