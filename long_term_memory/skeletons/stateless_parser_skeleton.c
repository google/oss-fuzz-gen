// Stateless Parser Pattern: Direct call, no setup/cleanup

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Input validation
  if (size < MIN_SIZE) return 0;
  if (size > MAX_SIZE) return 0;
  
  // Direct API call
  RESULT_TYPE *result = PARSE_FUNCTION(data, size);
  
  // Check and use result
  if (result != NULL) {
    // Access result fields if needed
    
    // Cleanup
    FREE_FUNCTION(result);
  }
  
  return 0;
}
