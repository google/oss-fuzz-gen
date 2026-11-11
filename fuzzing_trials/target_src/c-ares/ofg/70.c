#include <stddef.h>
#include <string.h>
#include <ares.h>
#include <arpa/nameser.h> // For C_IN and T_A

// Define a simple callback function for ares_query_dnsrec
static void dnsrec_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
  // This callback does nothing in this simple fuzzing example
  (void)arg; // Avoid unused parameter warning
  (void)status; // Avoid unused parameter warning
  (void)timeouts; // Avoid unused parameter warning
  (void)abuf; // Avoid unused parameter warning
  (void)alen; // Avoid unused parameter warning
}

int LLVMFuzzerTestOneInput_70(const unsigned char *data, size_t size) {
  ares_channel channel;
  struct ares_options options;
  int optmask = 0;
  unsigned short qid = 0;
  const char *name = "example.com"; // Use a valid domain name
  int dnsclass = C_IN; // Internet class
  int type = T_A; // Type A record

  // Initialize the ares library
  if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
    return 0;
  }

  // Initialize the ares channel
  if (ares_init_options(&channel, &options, optmask) != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  // Call the function-under-test
  ares_query_dnsrec(channel, name, dnsclass, type, dnsrec_callback, NULL, &qid);

  // Clean up the ares channel
  ares_destroy(channel);

  // Clean up the ares library
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

    LLVMFuzzerTestOneInput_70(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
