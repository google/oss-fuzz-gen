#include <ares.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

// Callback function for ares_getaddrinfo
static void my_callback(void *arg, int status, int timeouts, struct ares_addrinfo *res) {
  // Handle the callback results here
  (void)arg; // Suppress unused parameter warning
  (void)status; // Suppress unused parameter warning
  (void)timeouts; // Suppress unused parameter warning
  if (res) {
    ares_freeaddrinfo(res);
  }
}

int LLVMFuzzerTestOneInput_33(const uint8_t *data, size_t size) {
  // Initialize the ares library
  ares_library_init(ARES_LIB_INIT_ALL);

  // Create a channel
  ares_channel channel;
  if (ares_init(&channel) != ARES_SUCCESS) {
    return 0;
  }

  // Allocate memory for the name and service strings
  char *name = (char *)malloc(size + 1);
  char *service = (char *)malloc(size + 1);

  if (name == NULL || service == NULL) {
    free(name);
    free(service);
    ares_destroy(channel);
    return 0;
  }

  // Copy data into name and service strings
  memcpy(name, data, size);
  name[size] = '\0';
  memcpy(service, data, size);
  service[size] = '\0';

  // Set up hints
  struct ares_addrinfo_hints hints;
  hints.ai_flags = ARES_AI_CANONNAME;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;

  // Call the function-under-test
  ares_getaddrinfo(channel, name, service, &hints, my_callback, NULL);

  // Clean up
  free(name);
  free(service);
  ares_destroy(channel);
  ares_library_cleanup();

  return 0;
}