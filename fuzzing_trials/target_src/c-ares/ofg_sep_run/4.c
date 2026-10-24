#include <ares.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h> // For struct in_addr
#include <sys/types.h>  // For AF_INET
#include <netdb.h>      // For struct hostent

// Callback function for ares_gethostbyaddr
static void host_callback(void *arg, int status, int timeouts, struct hostent *host) {
  (void)arg;      // Suppress unused parameter warning
  (void)status;   // Suppress unused parameter warning
  (void)timeouts; // Suppress unused parameter warning
  (void)host;     // Suppress unused parameter warning
}

int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
  ares_channel channel;
  struct ares_options options;
  int optmask = 0;

  // Initialize ares library
  if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
    return 0;
  }

  // Initialize the channel
  if (ares_init_options(&channel, &options, optmask) != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  // Ensure the size is appropriate for an address
  if (size < sizeof(struct in_addr)) {
    ares_destroy(channel);
    ares_library_cleanup();
    return 0;
  }

  // Copy the data into an address buffer
  void *addr = malloc(size);
  if (addr == NULL) {
    ares_destroy(channel);
    ares_library_cleanup();
    return 0;
  }
  memcpy(addr, data, size);

  // Call the function-under-test
  ares_gethostbyaddr(channel, addr, (int)size, AF_INET, host_callback, NULL);

  // Clean up
  free(addr);
  ares_destroy(channel);
  ares_library_cleanup();

  return 0;
}