#include <ares.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>

// Callback function for ares_gethostbyname
static void host_callback(void *arg, int status, int timeouts, struct hostent *host) {
  // For the purpose of fuzzing, we don't need to do anything here.
}

int LLVMFuzzerTestOneInput_18(const uint8_t *data, size_t size) {
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

  // Ensure the data is null-terminated for use as a string
  char *name = (char *)malloc(size + 1);
  if (!name) {
    ares_destroy(channel);
    ares_library_cleanup();
    return 0;
  }
  memcpy(name, data, size);
  name[size] = '\0';

  int family = AF_INET;  // Use AF_INET as a default family

  // Call the function-under-test
  ares_gethostbyname(channel, name, family, host_callback, NULL);

  // Clean up
  free(name);
  ares_destroy(channel);
  ares_library_cleanup();

  return 0;
}