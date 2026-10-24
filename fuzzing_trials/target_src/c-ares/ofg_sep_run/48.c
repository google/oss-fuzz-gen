#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "ares.h"

int LLVMFuzzerTestOneInput_48(const unsigned char *data, size_t size) {
  // Initialize variables for ares_parse_a_reply
  struct hostent *host = NULL;
  struct ares_addrttl addrttls[5];
  int naddrttls = 5; // Number of addrttls, set to 5 for testing

  // Call the function-under-test
  ares_parse_a_reply(data, (int)size, &host, addrttls, &naddrttls);

  // Free the allocated hostent structure if it was allocated
  if (host) {
    ares_free_hostent(host);
  }

  return 0;
}