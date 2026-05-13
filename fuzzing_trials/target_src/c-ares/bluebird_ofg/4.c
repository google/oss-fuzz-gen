#include <sys/stat.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>  // Include this for INT_MAX
#include "ares.h"    // Include this for ares-related functions

// Remove the extern "C" linkage specification as it is not valid in C
int LLVMFuzzerTestOneInput_4(const unsigned char *data, size_t size);

int LLVMFuzzerTestOneInput_4(const unsigned char *data, size_t size) {
  /* Initialize the parameters for ares_parse_aaaa_reply */
  struct hostent *host = NULL;
  struct ares_addr6ttl addrttls[5];
  int naddrttls = 5;

  // Ensure that size is within a reasonable range for testing
  if (size > 0 && size <= INT_MAX) {
    // Call the function-under-test
    ares_parse_aaaa_reply(data, (int)size, &host, addrttls, &naddrttls);

    // Free the hostent structure if it was allocated
    if (host) {
      ares_free_hostent(host);
    }
  }

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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
