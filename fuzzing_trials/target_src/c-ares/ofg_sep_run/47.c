#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_47(const unsigned char *data, size_t size) {
  struct hostent *host = NULL;
  struct ares_addrttl addrttls[5];
  int naddrttls = 5;

  /* Call the function-under-test */
  ares_parse_a_reply(data, (int)size, &host, addrttls, &naddrttls);

  /* Free the hostent structure if it was allocated */
  if (host) {
    ares_free_hostent(host);
  }

  return 0;
}