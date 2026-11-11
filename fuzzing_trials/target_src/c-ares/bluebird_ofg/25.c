#include <sys/stat.h>
#include "ares.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

void dummy_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
  // Dummy callback function to satisfy the ares_send function requirements.
}

int LLVMFuzzerTestOneInput_25(const uint8_t* data, size_t size) {
  if (size < 1) {
    return 0;
  }

  ares_library_init(ARES_LIB_INIT_ALL);

  ares_channel channel;
  int status = ares_init(&channel);
  if (status != ARES_SUCCESS) {
    return 0;
  }

  int qlen = size > 1 ? size - 1 : 1; // Ensure qlen is at least 1
  const unsigned char* qbuf = data;

  // Validate the size of the buffer
  if (qlen > size) {
    ares_destroy(channel);
    ares_library_cleanup();
    return 0;
  }

  void* arg = NULL; // Argument for the callback, can be NULL

  ares_send(channel, qbuf, qlen, dummy_callback, arg);

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

    LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
