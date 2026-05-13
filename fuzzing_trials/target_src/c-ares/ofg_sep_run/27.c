#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <ares.h>

// Custom memory allocation functions
static void* custom_malloc(size_t size) {
    return malloc(size);
}

static void custom_free(void* ptr) {
    free(ptr);
}

static void* custom_realloc(void* ptr, size_t size) {
    return realloc(ptr, size);
}

int LLVMFuzzerTestOneInput_27(const uint8_t *data, size_t size) {
    // Ensure the data is large enough to extract an integer flag
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an integer flag from the data
    int flags = *(const int*)data;

    // Call the function-under-test
    ares_library_init_mem(flags, custom_malloc, custom_free, custom_realloc);

    return 0;
}