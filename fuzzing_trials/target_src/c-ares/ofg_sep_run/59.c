#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_59(const uint8_t *data, size_t size) {
  ares_channel channel;
  int status = ares_init(&channel);
  if (status != ARES_SUCCESS) {
    return 0;
  }

  /* Create a temporary file to simulate a resolv.conf or similar configuration */
  char filename[] = "/tmp/ares_fuzzXXXXXX";
  int fd = mkstemp(filename);
  if (fd == -1) {
    ares_destroy(channel);
    return 0;
  }

  /* Write the fuzzed data into the temporary file */
  if (write(fd, data, size) == -1) {
    close(fd);
    ares_destroy(channel);
    return 0;
  }
  close(fd);

  /* Set the channel to use the temporary configuration file */
  struct ares_options options;
  options.resolvconf_path = filename;
  int optmask = ARES_OPT_RESOLVCONF;
  ares_save_options(channel, &options, &optmask);

  /* Call the function under test */
  char *servers_csv = ares_get_servers_csv(channel);
  if (servers_csv) {
    ares_free_data(servers_csv);
  }

  /* Clean up */
  ares_destroy(channel);
  unlink(filename);

  return 0;
}