#include <ares.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h> // For AF_INET and SOCK_STREAM

static void dummy_callback(void *arg, int status, int timeouts, struct ares_addrinfo *res) {
  /* Dummy callback function for ares_getaddrinfo */
  (void)arg;
  (void)status;
  (void)timeouts;
  if (res) {
    ares_freeaddrinfo(res);
  }
}

int LLVMFuzzerTestOneInput_34(const uint8_t *data, size_t size) {
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

  const char *name = "example.com";
  const char *service = "http";
  struct ares_addrinfo_hints hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  ares_getaddrinfo(channel, name, service, &hints, dummy_callback, NULL);

  /* Clean up */
  ares_destroy(channel);
  ares_library_cleanup();

  return 0;
}