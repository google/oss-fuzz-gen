#include <stddef.h>
#include <ares.h>

/* Fuzzing function for ares_parse_aaaa_reply */
int LLVMFuzzerTestOneInput_72(const unsigned char *data, size_t size) {
  /* Initialize parameters for ares_parse_aaaa_reply */
  struct hostent *host = NULL;
  struct ares_addr6ttl addrttls[5];
  int naddrttls = 5;

  /* Call the function-under-test */
  ares_parse_aaaa_reply(data, (int)size, &host, addrttls, &naddrttls);

  /* Free the hostent structure if it was allocated */
  if (host) {
    ares_free_hostent(host);
  }

  return 0;
}