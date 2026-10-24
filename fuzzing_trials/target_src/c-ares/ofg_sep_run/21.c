#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_21(const uint8_t *data, size_t size) {
  /* Initialize ares library */
  if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
    return 0;
  }

  ares_channel channel;
  int status = ares_init(&channel);
  if (status != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  /* Ensure the data is null-terminated to be used as a string */
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