#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_73(const uint8_t *data, size_t size) {
  /* Initialize the c-ares library */
  ares_library_init(ARES_LIB_INIT_ALL);

  /* Initialize a channel */
  ares_channel channel;
  int status = ares_init(&channel);
  if (status != ARES_SUCCESS) {
    return 0;
  }

  /* Ensure the input data is null-terminated */
  char *csv = (char *)malloc(size + 1);
  if (!csv) {
    ares_destroy(channel);
    return 0;
  }
  memcpy(csv, data, size);
  csv[size] = '\0';

  /* Call the function-under-test */
  ares_set_servers_ports_csv(&channel, csv);

  /* Clean up */
  free(csv);
  ares_destroy(channel);
  ares_library_cleanup();

  return 0;
}