#include <gdbm.h>
#include <stdint.h>
#include <stddef.h> // Include for size_t

int LLVMFuzzerTestOneInput_155(const uint8_t *data, size_t size) {
  // Call the function-under-test
  int *errno_location = gdbm_errno_location();

  // Ensure the function call is utilized to avoid optimization removal
  if (errno_location != NULL) {
    // Perform some operation with the returned pointer
    // For example, set the error number to a known value
    *errno_location = GDBM_NO_ERROR;
  }

  return 0;
}