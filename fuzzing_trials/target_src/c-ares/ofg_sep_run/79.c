#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <ares.h>
#include <netdb.h>  // Include this library to define 'struct hostent'

int LLVMFuzzerTestOneInput_79(const unsigned char *data, size_t size) {
  /* Ensure the input size is sufficient for testing */
  if (size < 1) {
    return 0;
  }

  /* Allocate memory for the hostent structure */
  struct hostent *host = (struct hostent *)malloc(sizeof(struct hostent));
  if (!host) {
    return 0;
  }
  memset(host, 0, sizeof(struct hostent));

  /* Call the function-under-test */
  ares_parse_ns_reply(data, (int)size, &host);

  /* Free the allocated hostent structure */
  if (host) {
    ares_free_hostent(host);
  }

  return 0;
}