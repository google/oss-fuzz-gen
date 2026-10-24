#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>
#include <arpa/nameser.h> // Include for DNS class and type definitions

static void dummy_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
  // Dummy callback function to satisfy the ares_search function signature.
  (void)arg; // Suppress unused parameter warning
  (void)status; // Suppress unused parameter warning
  (void)timeouts; // Suppress unused parameter warning
  (void)abuf; // Suppress unused parameter warning
  (void)alen; // Suppress unused parameter warning
}

int LLVMFuzzerTestOneInput_19(const uint8_t *data, size_t size) {
  ares_channel channel;
  int status = ares_init(&channel);
  if (status != ARES_SUCCESS) {
    return 0;
  }

  // Ensure the input data is null-terminated for a valid domain name.
  char *name = (char *)malloc(size + 1);
  if (name == NULL) {
    ares_destroy(channel);
    return 0;
  }
  memcpy(name, data, size);
  name[size] = '\0';

  // Define DNS class and type with some valid values.
  int dnsclass = C_IN; // Internet class
  int type = T_A;      // A record type

  // Call the function-under-test.
  ares_search(channel, name, dnsclass, type, dummy_callback, NULL);

  // Clean up.
  free(name);
  ares_destroy(channel);

  return 0;
}