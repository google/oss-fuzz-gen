#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_46(const unsigned char *data, unsigned long size);

int LLVMFuzzerTestOneInput_46(const unsigned char *data, unsigned long size) {
  struct ares_soa_reply *soa_out = NULL;

  // Call the function-under-test
  ares_parse_soa_reply(data, (int)size, &soa_out);

  // Free the allocated memory if the parsing was successful
  if (soa_out) {
    ares_free_data(soa_out);
  }

  return 0;
}