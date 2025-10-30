// Stream Processor Skeleton
// Pattern: init → while(has_data) { process_chunk } → finalize
// NOTE: Headers are provided above this skeleton - DO NOT add additional headers

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Input validation
  if (size < MIN_SIZE) return 0;
  
  // Step 1: Initialize stream
  STREAM_TYPE *stream = STREAM_INIT();
  if (!stream) return 0;
  
  STREAM_CONFIGURE(stream);
  
  if (STREAM_OPEN(stream, data, size) != OK) {
    STREAM_FREE(stream);
    return 0;
  }
  
  // Step 2: Process stream in loop
  ENTRY_TYPE *entry;
  int max_entries = 100;  // CRITICAL: prevent infinite loop
  
  while (max_entries-- > 0) {
    int ret = STREAM_NEXT(stream, &entry);
    
    if (ret == EOF) break;      // Normal end
    if (ret != OK) break;       // Error
    
    // Process entry data in chunks
    uint8_t buffer[4096];
    ssize_t n;
    int max_reads = 1000;  // CRITICAL: prevent infinite loop
    
    while ((n = STREAM_READ(stream, buffer, sizeof(buffer))) > 0 
           && max_reads-- > 0) {
      // Process chunk
      // ...
    }
    
    if (n < 0) break;  // Read error
  }
  
  // Step 3: Finalize
  STREAM_CLOSE(stream);
  STREAM_FREE(stream);
  return 0;
}

