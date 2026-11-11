#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ares.h>
#include <ares_dns.h>
#include <arpa/nameser.h> // Include for C_IN and T_A

// Callback function for ares_query
static void query_callback(void *arg, int status, int timeouts, const unsigned char *abuf, int alen) {
  (void)arg; // Suppress unused parameter warning
  (void)status; // Suppress unused parameter warning
  (void)timeouts; // Suppress unused parameter warning
  (void)abuf; // Suppress unused parameter warning
  (void)alen; // Suppress unused parameter warning
  // This is a simple callback function that does nothing.
  // In a real application, you would process the DNS response here.
}

int LLVMFuzzerTestOneInput_63(const uint8_t *data, size_t size) {
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

  // Ensure that the data is null-terminated for use as a string
  char *name = (char *)malloc(size + 1);
  if (name == NULL) {
    ares_destroy(channel);
    ares_library_cleanup();
    return 0;
  }
  memcpy(name, data, size);
  name[size] = '\0';

  int dnsclass = C_IN; // Internet class
  int type = T_A; // A record type

  // Call the function-under-test
  ares_query(channel, name, dnsclass, type, query_callback, NULL);

  // Clean up
  ares_destroy(channel);
  ares_library_cleanup();
  free(name);

  return 0;
}