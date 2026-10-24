#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "ares.h"

int LLVMFuzzerTestOneInput_91(const uint8_t *data, size_t size) {
  /* Ensure size is sufficient to create a hostent structure */
  if (size < sizeof(struct hostent)) {
    return 0;
  }

  /* Allocate memory for hostent structure */
  struct hostent *host = (struct hostent *)malloc(sizeof(struct hostent));
  if (!host) {
    return 0;
  }

  /* Initialize hostent fields with non-NULL values */
  host->h_name = (char *)malloc(256);
  host->h_aliases = (char **)malloc(2 * sizeof(char *));
  host->h_aliases[0] = (char *)malloc(256);
  host->h_aliases[1] = NULL;
  host->h_addrtype = AF_INET;
  host->h_length = sizeof(struct in_addr);
  host->h_addr_list = (char **)malloc(2 * sizeof(char *));
  host->h_addr_list[0] = (char *)malloc(sizeof(struct in_addr));
  host->h_addr_list[1] = NULL;

  /* Fill with some data */
  strncpy(host->h_name, "example.com", 255);
  strncpy(host->h_aliases[0], "alias.example.com", 255);
  inet_pton(AF_INET, "192.0.2.1", host->h_addr_list[0]);

  /* Call the function-under-test */
  ares_free_hostent(host);

  return 0;
}