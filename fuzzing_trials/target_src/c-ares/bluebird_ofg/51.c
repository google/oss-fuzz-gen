#include <sys/stat.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "ares.h"
#include <arpa/nameser.h> // Include for C_IN and T_A

static void dummy_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
  (void)arg; // Suppress unused parameter warning
  (void)status; // Suppress unused parameter warning
  (void)timeouts; // Suppress unused parameter warning
  (void)abuf; // Suppress unused parameter warning
  (void)alen; // Suppress unused parameter warning
  /* Dummy callback function for ares_query */
}

int LLVMFuzzerTestOneInput_51(const unsigned char *data, size_t size) {
  ares_channel channel;
  int status;
  struct ares_options options;
  int optmask = 0;

  // Initialize the ares library
  status = ares_library_init(ARES_LIB_INIT_ALL);
  if (status != ARES_SUCCESS) {
    return 0;
  }

  // Initialize the ares channel
  status = ares_init_options(&channel, &options, optmask);
  if (status != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  // Ensure the data is null-terminated for use as a string
  char *name = (char *)malloc(size + 1);
  if (name == NULL) {
    ares_destroy(channel);
    ares_library_cleanup();
    return 0;
  }
  memcpy(name, data, size);
  name[size] = '\0';

  // Call the function-under-test
  ares_query(channel, name, C_IN, T_A, dummy_callback, NULL);

  // Clean up
  free(name);
  ares_destroy(channel);
  ares_library_cleanup();

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

    LLVMFuzzerTestOneInput_51(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
