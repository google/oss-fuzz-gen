#include <ares.h>
#include <ares_nameser.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Fuzzer entry point
int LLVMFuzzerTestOneInput_51(const uint8_t *data, size_t size) {
  ares_channel channel = NULL;
  int status;

  // Initialize the ares library
  status = ares_library_init(ARES_LIB_INIT_ALL);
  if (status != ARES_SUCCESS) {
    return 0;
  }

  // Initialize the channel
  status = ares_init(&channel);
  if (status != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  // Check if size is sufficient for a valid query
  if (size > 0) {
    // Call the function-under-test
    ares_query(channel, (const char *)data, ns_c_in, ns_t_a, NULL, NULL);
  }

  // Clean up
  ares_destroy(channel);
  ares_library_cleanup();

  return 0;
}

#ifdef __cplusplus
}
#endif