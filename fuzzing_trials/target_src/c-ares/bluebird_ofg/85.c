#include <sys/stat.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "ares.h"
#include <netdb.h>

static void test_callback(void *arg, int status, int timeouts, struct hostent *host) {
  // Callback function for ares_gethostbyname
  // This function can be used to handle the result of the DNS query.
  (void)arg;
  (void)status;
  (void)timeouts;
  (void)host;
}

int LLVMFuzzerTestOneInput_85(const unsigned char *data, size_t size) {
  ares_channel channel;
  struct ares_options options;
  int optmask = 0;
  int status;

  // Initialize ares library
  status = ares_library_init(ARES_LIB_INIT_ALL);
  if (status != ARES_SUCCESS) {
    return 0;
  }

  // Initialize ares channel
  // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 2 of ares_init_options
  status = ares_init_options(&channel, &options, ARES_OPT_EDNSPSZ);
  // End mutation: Producer.REPLACE_ARG_MUTATOR
  if (status != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  // Ensure the input data is null-terminated for use as a string
  char *name = (char *)malloc(size + 1);
  if (!name) {
    ares_destroy(channel);
    ares_library_cleanup();
    return 0;
  }
  memcpy(name, data, size);
  name[size] = '\0';

  // Use ares_gethostbyname with the provided data
  ares_gethostbyname(channel, name, AF_INET, test_callback, NULL);

  // Cleanup
  ares_destroy(channel);
  ares_library_cleanup();
  free(name);

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

    LLVMFuzzerTestOneInput_85(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
