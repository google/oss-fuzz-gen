// Object Lifecycle Pattern: create → use → destroy

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < MIN_SIZE) return 0;
  
  // Step 1: Create object
  OBJECT_TYPE *obj = OBJECT_CREATE();
  if (!obj) return 0;
  
  // Step 2: Use object
  int ret = OBJECT_PROCESS(obj, data, size);
  if (ret < 0) goto cleanup;
  
  // Optional: More operations
  // ret = OBJECT_QUERY(obj);
  // if (ret < 0) goto cleanup;
  
  // Step 3: Destroy
cleanup:
  OBJECT_DESTROY(obj);
  return 0;
}
