#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <ares.h>
#include <ares_dns.h> // Include for ares_dns_addr_to_ptr
#include <ares_nameser.h> // Include for struct ares_addr

int LLVMFuzzerTestOneInput_26(const uint8_t *data, size_t size) {
  if (size < sizeof(struct ares_addr)) {
    return 0;
  }

  struct ares_addr addr;
  memcpy(&addr, data, sizeof(struct ares_addr));

  char *result = ares_dns_addr_to_ptr(&addr);
  if (result) {
    ares_free_string(result);
  }

  return 0;
}