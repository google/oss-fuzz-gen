#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>
#include <arpa/nameser.h>  // Include for C_IN and T_A

// Declare the dummy_callback function as static since it is only used within this file
static void dummy_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
  (void)arg;     // Explicitly mark parameters as unused
  (void)status;  // to avoid compiler warnings
  (void)timeouts;
  (void)abuf;
  (void)alen;
  /* A simple dummy callback function */
}

// Declare the prototype for the fuzzer function as static
int LLVMFuzzerTestOneInput_42(const uint8_t *data, size_t size) {
  if (size == 0) return 0; // Ensure non-null input

  ares_channel channel;
  ares_library_init(ARES_LIB_INIT_ALL);
  if (ares_init(&channel) != ARES_SUCCESS) {
    return 0;
  }

  // Using ares_query instead of ares_search_dnsrec for proper function usage
  ares_query(channel, (const char *)data, C_IN, T_A, dummy_callback, NULL);

  ares_destroy(channel);
  ares_library_cleanup();

  return 0;
}