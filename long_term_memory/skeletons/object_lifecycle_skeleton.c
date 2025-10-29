// Object Lifecycle Skeleton
// Pattern: create → use → destroy

#include <stddef.h>
#include <stdint.h>
// Include target API headers here

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Input validation
  if (size < MIN_SIZE) return 0;
  
  // Step 1: Create object
  OBJECT_TYPE *obj = OBJECT_CREATE();
  if (!obj) return 0;  // Postcondition: check NULL
  
  // Step 2: Use object
  int ret = OBJECT_PROCESS(obj, data, size);
  if (ret < 0) goto cleanup;  // Postcondition: check error
  
  // Optional: More operations on object
  // ret = OBJECT_QUERY(obj);
  // if (ret < 0) goto cleanup;
  
  // Step 3: Destroy
cleanup:
  OBJECT_DESTROY(obj);
  return 0;
}

