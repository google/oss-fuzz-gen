#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdint.h> // Include this header for uint8_t type
#include "ares.h"

int LLVMFuzzerTestOneInput_139(const uint8_t *data, size_t size) {
  if (size < sizeof(struct hostent)) {
    return 0; /* Not enough data to create a valid hostent structure */
  }

  // Allocate memory for the hostent structure
  struct hostent *host = (struct hostent *)malloc(sizeof(struct hostent));
  if (!host) {
    return 0; /* Memory allocation failed */
  }

  // Initialize the hostent structure with some dummy values
  host->h_name = (char *)data;
  host->h_aliases = NULL;
  host->h_addrtype = AF_INET;
  host->h_length = sizeof(struct in_addr);
  host->h_addr_list = (char **)malloc(2 * sizeof(char *));
  if (!host->h_addr_list) {
    free(host);
    return 0; /* Memory allocation failed */
  }

  host->h_addr_list[0] = (char *)malloc(sizeof(struct in_addr));
  if (!host->h_addr_list[0]) {
    free(host->h_addr_list);
    free(host);
    return 0; /* Memory allocation failed */
  }

  memcpy(host->h_addr_list[0], data, sizeof(struct in_addr));
  host->h_addr_list[1] = NULL;

  // Call the function-under-test
  ares_free_hostent(host);

  return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_139(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
