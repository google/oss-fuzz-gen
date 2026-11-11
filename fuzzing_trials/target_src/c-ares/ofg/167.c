#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <ares.h>

static void server_state_callback(void *data, int state) {
  /* Example callback function implementation */
  (void)data;  /* Suppress unused parameter warning */
  (void)state; /* Suppress unused parameter warning */
}

int LLVMFuzzerTestOneInput_167(const uint8_t *data, size_t size) {
  ares_channel channel;
  int status = ares_init(&channel);
  if (status != ARES_SUCCESS) {
    return 0;
  }

  /* Use the data as the callback data */
  void *callback_data = (void *)data;

  /* Set the server state callback */
  ares_set_server_state_callback(channel, server_state_callback, callback_data);

  /* Clean up */
  ares_destroy(channel);

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

    LLVMFuzzerTestOneInput_167(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
