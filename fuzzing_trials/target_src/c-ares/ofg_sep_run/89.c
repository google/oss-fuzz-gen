#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <ares.h>
#include <netinet/in.h> // For AF_INET

int LLVMFuzzerTestOneInput_89(const uint8_t *data, size_t size) {
  ares_channel channel;
  struct hostent *host = NULL;
  int family = AF_INET; /* Default to IPv4 */

  // Initialize the ares library
  if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
    return 0;
  }

  // Initialize ares channel
  if (ares_init(&channel) != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  // Ensure that the name is null-terminated
  char name[256];
  if (size > 255) {
    size = 255;
  }
  memcpy(name, data, size);
  name[size] = '\0';

  // Call the function-under-test
  ares_gethostbyname_file(channel, name, family, &host);

  // Clean up
  if (host) {
    ares_free_hostent(host);
  }
  ares_destroy(channel);
  ares_library_cleanup();

  return 0;
}