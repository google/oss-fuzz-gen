/* Code ported from c-ares test/ares-test-fuzz.c */
#include <stddef.h>

#include "ares.h"

// Entrypoint for Clang's libfuzzer
int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {
  // Feed the data into each of the ares_parse_*_reply functions.
  struct hostent *host = NULL;
  ares_parse_a_reply(data, size, &host);
  if (host)
    ares_free_hostent(host);

  host = NULL;
  unsigned char addrv4[4] = {0x10, 0x20, 0x30, 0x40};
  ares_parse_ptr_reply(data, size, addrv4, sizeof(addrv4), AF_INET, &host);
  if (host)
    ares_free_hostent(host);

  return 0;
}
