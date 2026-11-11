#include <ares.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

void dummy_callback(void *arg, int status, int timeouts, struct hostent *host) {
  // Dummy callback function for ares_gethostbyaddr
}

int LLVMFuzzerTestOneInput_3(const uint8_t *data, size_t size) {
  if (size == 0) {
    return 0;
  }

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

  // Determine family and address length
  int family = (data[0] % 2 == 0) ? AF_INET : AF_INET6;
  int addrlen = (family == AF_INET) ? 4 : 16;

  if (size < addrlen + 1) {
    ares_destroy(channel);
    ares_library_cleanup();
    return 0;
  }

  // Extract address from data
  const void *addr = data + 1;

  // Dummy argument
  void *arg = NULL;

  // Call the function-under-test
  ares_gethostbyaddr(channel, addr, addrlen, family, dummy_callback, arg);

  // Clean up
  ares_destroy(channel);
  ares_library_cleanup();

  return 0;
}