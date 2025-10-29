// Stateless Parser Skeleton
// Pattern: Direct call, no setup/cleanup needed

#include <stddef.h>
#include <stdint.h>
// Include target API headers here

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Input validation
  if (size < MIN_SIZE) return 0;
  if (size > MAX_SIZE) return 0;
  
  // Direct API call - no setup needed
  RESULT_TYPE *result = PARSE_FUNCTION(data, size);
  
  // Optional: check result and use it
  if (result != NULL) {
    // Access result fields if needed
    // ...
    
    // Free result if necessary
    FREE_FUNCTION(result);
  }
  
  return 0;
}

