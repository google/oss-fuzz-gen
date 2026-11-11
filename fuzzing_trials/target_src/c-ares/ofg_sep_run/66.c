#include <stddef.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_66(const unsigned char *data, size_t size) {
  if (size < sizeof(struct in_addr)) {
    return 0;
  }

  struct hostent *host = NULL;
  struct in_addr addr;
  int family = AF_INET;
  int addrlen = sizeof(struct in_addr);

  // Copy the first part of data to addr
  memcpy(&addr, data, sizeof(struct in_addr));

  // Call the function under test
  ares_parse_ptr_reply(data, (int)size, &addr, addrlen, family, &host);

  // Free the hostent if it was allocated
  if (host) {
    ares_free_hostent(host);
  }

  return 0;
}