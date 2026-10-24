#include <stddef.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_67(const unsigned char *data, unsigned long size) {
  struct hostent *host = NULL;
  unsigned char addr4[4] = {192, 0, 2, 1}; // Example IPv4 address
  unsigned char addr6[16] = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
                             0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34}; // Example IPv6 address

  // Try parsing as IPv4
  ares_parse_ptr_reply(data, (int)size, addr4, sizeof(addr4), AF_INET, &host);
  if (host) {
    ares_free_hostent(host);
    host = NULL;
  }

  // Try parsing as IPv6
  ares_parse_ptr_reply(data, (int)size, addr6, sizeof(addr6), AF_INET6, &host);
  if (host) {
    ares_free_hostent(host);
  }

  return 0;
}