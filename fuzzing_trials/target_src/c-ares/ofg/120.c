#include <ares.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_120(const uint8_t *data, size_t size) {
  ares_channel channel;
  struct ares_options options;
  int optmask = 0;

  /* Initialize the ares library */
  if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
    return 0;
  }

  /* Initialize the ares channel */
  if (ares_init_options(&channel, &options, optmask) != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  /* Create pipe file descriptors for read and write */
  int pipe_fds[2];
  if (pipe(pipe_fds) == -1) {
    ares_destroy(channel);
    ares_library_cleanup();
    return 0;
  }

  /* Use the pipe file descriptors as read_fd and write_fd */
  ares_socket_t read_fd = pipe_fds[0];
  ares_socket_t write_fd = pipe_fds[1];

  /* Call the function-under-test */
  ares_process_fd(channel, read_fd, write_fd);

  /* Clean up */
  close(read_fd);
  close(write_fd);
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

    LLVMFuzzerTestOneInput_120(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
