#include <stddef.h>
#include <sys/time.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_74(const unsigned char *data, size_t size) {
  ares_channel channel;
  struct timeval maxtv;
  struct timeval tvbuf;

  /* Initialize the ares library */
  if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
    return 0;
  }

  /* Initialize the ares channel */
  if (ares_init(&channel) != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  /* Setup the maxtv and tvbuf with some values */
  maxtv.tv_sec = 1;
  maxtv.tv_usec = 0;
  tvbuf.tv_sec = 0;
  tvbuf.tv_usec = 0;

  /* Call the function-under-test */
  struct timeval *result = ares_timeout(channel, &maxtv, &tvbuf);

  /* Cleanup */
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

    LLVMFuzzerTestOneInput_74(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
