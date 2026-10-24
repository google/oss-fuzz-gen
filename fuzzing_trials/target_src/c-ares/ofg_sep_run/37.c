#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_37(const uint8_t *data, size_t size) {
  /* Ensure that the data is large enough to fill ares_options */
  if (size < sizeof(struct ares_options)) {
    return 0;
  }

  /* Allocate memory for ares_options and copy data into it */
  struct ares_options *options = (struct ares_options *)malloc(sizeof(struct ares_options));
  if (options == NULL) {
    return 0;
  }
  
  memcpy(options, data, sizeof(struct ares_options));

  /* Call the function under test */
  ares_destroy_options(options);

  /* Free the allocated memory */
  free(options);

  return 0;
}