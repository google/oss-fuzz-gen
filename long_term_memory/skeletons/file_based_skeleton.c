// File-based API Skeleton
// Pattern: write_temp → api_load_file → unlink
// NOTE: Headers are provided above this skeleton - DO NOT add additional headers

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Input validation
  if (size < 1) return 0;
  
  // Create unique temp filename
  char filename[256];
  snprintf(filename, sizeof(filename), "/tmp/fuzz_%d_%p", 
           getpid(), (void*)data);
  
  // Write data to temp file
  FILE *fp = fopen(filename, "wb");
  if (!fp) return 0;
  
  fwrite(data, 1, size, fp);
  fclose(fp);
  
  // Call API with filename
  RESULT_TYPE *result = API_LOAD_FILE(filename);
  
  // Use result
  if (result) {
    // Process result
    // ...
    
    API_FREE_RESULT(result);
  }
  
  // Cleanup temp file
  unlink(filename);
  return 0;
}

