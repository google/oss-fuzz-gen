#include <stddef.h>
#include <sys/select.h>
#include <ares.h>

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_131(const uint8_t *data, size_t size) {
  ares_channel channel;
  int status;
  struct ares_options options;
  int optmask = 0;

  /* Initialize the ares library */
  status = ares_library_init(ARES_LIB_INIT_ALL);
  if (status != ARES_SUCCESS) {
    return 0;
  }

  /* Initialize the ares channel */
  status = ares_init_options(&channel, &options, optmask);
  if (status != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  /* Prepare fd_set structures */
  fd_set read_fds;
  fd_set write_fds;
  FD_ZERO(&read_fds);
  FD_ZERO(&write_fds);

  /* Call the function-under-test */
  ares_fds(channel, &read_fds, &write_fds);

  /* Clean up */
  ares_destroy(channel);
  ares_library_cleanup();

  return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_131(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
