#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assuming the function ares_free_data is declared in a header file for the ares library
extern void ares_free_data(void *dataptr);

int LLVMFuzzerTestOneInput_10(const uint8_t* data, size_t size) {
  // Allocate some memory to be freed
  size_t dataSize = size > 0 ? size : 1; // Ensure at least 1 byte is allocated
  void* dataptr = malloc(dataSize);
  if (dataptr == NULL) {
    return 0;
  }

  // Fill the allocated memory with fuzzed data
  memcpy(dataptr, data, dataSize);

  // Call the function under test
  ares_free_data(dataptr);

  return 0;
}