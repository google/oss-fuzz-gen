#include <stddef.h>
#include <stdlib.h>
#include <ares.h>

// Custom memory allocation functions
void *custom_malloc(size_t size) {
    return malloc(size);
}

void custom_free(void *ptr) {
    free(ptr);
}

void *custom_realloc(void *ptr, size_t size) {
    return realloc(ptr, size);
}

int LLVMFuzzerTestOneInput_28(const unsigned char *data, size_t size) {
    // Use the data to determine flags
    int flags = 0;
    if (size > 0) {
        flags = data[0];
    }

    // Call the function-under-test
    int result = ares_library_init_mem(flags, custom_malloc, custom_free, custom_realloc);

    // Ensure the library is cleaned up after initialization
    if (result == ARES_SUCCESS) {
        ares_library_cleanup();
    }

    return 0;
}