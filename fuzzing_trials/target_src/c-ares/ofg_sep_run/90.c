#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "ares.h"

int LLVMFuzzerTestOneInput_90(const unsigned char *data, size_t size) {
  /* Allocate memory for a hostent structure */
  struct hostent *host = (struct hostent *)malloc(sizeof(struct hostent));
  if (host == NULL) {
    return 0; /* Exit if memory allocation fails */
  }

  /* Initialize the hostent structure with some non-NULL values */
  host->h_name = (char *)malloc(256);
  host->h_aliases = (char **)malloc(sizeof(char *) * 2);
  host->h_addr_list = (char **)malloc(sizeof(char *) * 2);
  if (host->h_name == NULL || host->h_aliases == NULL || host->h_addr_list == NULL) {
    free(host->h_name);
    free(host->h_aliases);
    free(host->h_addr_list);
    free(host);
    return 0; /* Exit if memory allocation fails */
  }

  /* Populate the fields with dummy data */
  strncpy(host->h_name, "example.com", 256);
  host->h_aliases[0] = strdup("alias1");
  host->h_aliases[1] = NULL;
  host->h_addrtype = AF_INET;
  host->h_length = 4;
  host->h_addr_list[0] = (char *)malloc(host->h_length);
  host->h_addr_list[1] = NULL;
  if (host->h_addr_list[0] == NULL) {
    free(host->h_name);
    free(host->h_aliases[0]);
    free(host->h_aliases);
    free(host->h_addr_list);
    free(host);
    return 0; /* Exit if memory allocation fails */
  }
  memset(host->h_addr_list[0], 0, host->h_length);

  /* Call the function under test */
  ares_free_hostent(host);

  return 0;
}