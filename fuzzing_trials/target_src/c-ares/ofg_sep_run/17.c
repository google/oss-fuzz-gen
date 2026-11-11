#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <ares.h>
#include <sys/socket.h> // For AF_INET

static void dummy_callback(void *arg, int status, int timeouts, struct hostent *host) {
  /* Dummy callback function to satisfy the ares_gethostbyname requirements */
  (void)arg;
  (void)status;
  (void)timeouts;
  (void)host;
}

int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
  ares_channel channel;
  int status = ares_library_init(ARES_LIB_INIT_ALL);
  if (status != ARES_SUCCESS) {
    return 0;
  }

  status = ares_init(&channel);
  if (status != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  /* Ensure the name is null-terminated */
  char name[256];
  size_t name_len = size < 255 ? size : 255;
  memcpy(name, data, name_len);
  name[name_len] = '\0';

  int family = AF_INET; /* Use AF_INET for IPv4 as a default family */
  ares_gethostbyname(channel, name, family, dummy_callback, NULL);

  /* Process any pending queries */
  ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);

  ares_destroy(channel);
  ares_library_cleanup();

  return 0;
}