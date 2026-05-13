#include <stddef.h>
#include <stdlib.h>
#include <ares.h>

// Forward declaration of the callback function
static void dummy_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen);

int LLVMFuzzerTestOneInput_72(const unsigned char *data, size_t size) {
  ares_channel channel; // Correct the type name
  struct ares_options options;
  int optmask = 0;
  int status;

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

  // Use the provided data as the query buffer
  const unsigned char *qbuf = data;
  int qlen = (int)size;
  void *arg = NULL; // No specific argument needed for the callback

  // Call the function-under-test
  ares_send(channel, qbuf, qlen, dummy_callback, arg);

  // Clean up the ares channel
  ares_destroy(channel);

  // Clean up the ares library
  ares_library_cleanup();

  return 0;
}

// Dummy callback function to be used with ares_send
static void dummy_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
  (void)arg; // Suppress unused parameter warning
  (void)status; // Suppress unused parameter warning
  (void)timeouts; // Suppress unused parameter warning
  (void)abuf; // Suppress unused parameter warning
  (void)alen; // Suppress unused parameter warning
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

    LLVMFuzzerTestOneInput_72(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
