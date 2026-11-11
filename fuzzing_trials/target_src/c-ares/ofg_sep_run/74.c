#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_74(const uint8_t *data, size_t size) {
  ares_channel channel; // Corrected type from ares_channel_t to ares_channel
  int status = ares_init(&channel);
  if (status != ARES_SUCCESS) {
    return 0;
  }

  /* Ensure the input data is null-terminated to be used as a CSV string */
  char *csv = (char *)malloc(size + 1);
  if (csv == NULL) {
    ares_destroy(channel);
    return 0;
  }
  memcpy(csv, data, size);
  csv[size] = '\0';

  // Call the function under test
  ares_set_servers_ports_csv(channel, csv);

  // Clean up
  free(csv);
  ares_destroy(channel);

  return 0;
}