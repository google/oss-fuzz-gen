#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>
#include <ares_nameser.h> // Corrected include for C_IN and T_A

static void dummy_callback(void *arg, int status, int timeouts, const unsigned char *abuf, int alen) {
  // This is a dummy callback function for ares_query
  (void)arg;
  (void)status;
  (void)timeouts;
  (void)abuf;
  (void)alen;
}

int LLVMFuzzerTestOneInput_106(const unsigned char *data, size_t size) {
  if (size < 1) {
    return 0;
  }

  ares_channel channel; // Corrected type name
  int dnsclass = C_IN; // Internet class
  int type = T_A; // Type A (host address)
  void *arg = NULL;

  // Initialize the ares library
  if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
    return 0;
  }

  // Initialize the channel
  if (ares_init(&channel) != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  // Use the data as the name, ensuring it's null-terminated
  char *name = (char *)malloc(size + 1);
  if (!name) {
    ares_destroy(channel);
    ares_library_cleanup();
    return 0;
  }
  memcpy(name, data, size);
  name[size] = '\0';

  // Call the function-under-test
  ares_query(channel, name, dnsclass, type, dummy_callback, arg);

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

    LLVMFuzzerTestOneInput_106(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
