#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_20(const uint8_t *data, size_t size) {
  ares_channel channel;
  int status;

  /* Initialize ares library */
  status = ares_library_init(ARES_LIB_INIT_ALL);
  if (status != ARES_SUCCESS) {
    return 0;
  }

  /* Initialize ares channel */
  status = ares_init(&channel);
  if (status != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  /* Ensure the input data is null-terminated for use as a string */
  char *sortstr = (char *)malloc(size + 1);
  if (sortstr == NULL) {
    ares_destroy(channel);
    ares_library_cleanup();
    return 0;
  }
  memcpy(sortstr, data, size);
  sortstr[size] = '\0';

  /* Call the function under test */
  ares_set_sortlist(channel, sortstr);

  /* Clean up */
  free(sortstr);
  ares_destroy(channel);
  ares_library_cleanup();

  return 0;
}