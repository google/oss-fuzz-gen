#include <stddef.h>
#include <sys/select.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_24(const unsigned char *data, size_t size) {
  /* Initialize the ares library */
  ares_library_init(ARES_LIB_INIT_ALL);

  /* Create a channel */
  ares_channel channel;
  int status = ares_init(&channel);
  if (status != ARES_SUCCESS) {
    return 0;
  }

  /* Initialize fd_set structures */
  fd_set read_fds;
  fd_set write_fds;

  /* Clear the fd_set structures */
  FD_ZERO(&read_fds);
  FD_ZERO(&write_fds);

  /* Call the function-under-test */
  ares_fds(channel, &read_fds, &write_fds);

  /* Clean up */
  ares_destroy(channel);
  ares_library_cleanup();

  return 0;
}