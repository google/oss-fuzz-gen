#include <string.h>
#include <sys/stat.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "ares.h"

int LLVMFuzzerTestOneInput_70(const uint8_t *data, size_t size) {
  ares_channel channel;
  struct ares_options options;
  int optmask = 0;

  /* Initialize the ares library */
  if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
    return 0;
  }

  /* Set up ares options */
  options.timeout = 5000; /* 5 seconds timeout */
  options.tries = 3;      /* Number of tries */
  optmask |= ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES;

  /* Initialize ares channel */
  if (ares_init_options(&channel, &options, optmask) != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  /* Use the fuzzing data to determine the timeout */
  int timeout_ms = 0;
  if (size >= sizeof(int)) {
    timeout_ms = *(int *)data;
  }

  /* Call the function under test */
  ares_queue_wait_empty(channel, timeout_ms);

  /* Clean up */
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

    LLVMFuzzerTestOneInput_70(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
