#include <sys/stat.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h> // Include for file operations
#include "ares.h"
#include <arpa/nameser.h>

// Dummy callback function
static void dummy_callback(void *arg, int status, int timeouts, const unsigned char *abuf, int alen) {
  (void)arg; // Suppress unused parameter warning
  (void)status; // Suppress unused parameter warning
  (void)timeouts; // Suppress unused parameter warning
  (void)abuf; // Suppress unused parameter warning
  (void)alen; // Suppress unused parameter warning
}

int LLVMFuzzerTestOneInput_7(const unsigned char *data, size_t size) {
  ares_channel channel;
  struct ares_options options;
  int optmask = 0;
  int status;

  // Initialize the ares library
  status = ares_library_init(ARES_LIB_INIT_ALL);
  if (status != ARES_SUCCESS) {
    return 0;
  }

  // Initialize the ares channel
  memset(&options, 0, sizeof(options)); // Initialize options to zero
  status = ares_init_options(&channel, &options, optmask);
  if (status != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  // Ensure the name is null-terminated
  char *name = (char *)malloc(size + 1);
  if (!name) {
    ares_destroy(channel);
    ares_library_cleanup();
    return 0;
  }
  memcpy(name, data, size);
  name[size] = '\0';

  // Fuzz the ares_search function
  ares_search(channel, name, ns_c_in, ns_t_a, dummy_callback, NULL);

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

    LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
