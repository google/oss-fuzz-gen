#include "cstdint"
#include "cstdlib"
#include <cstring>
#include <iostream>

// Define the function pointer types for memory allocation functions
typedef void* (*_cbor_malloc_t)(size_t size);
typedef void* (*_cbor_realloc_t)(void* ptr, size_t size);
typedef void (*_cbor_free_t)(void* ptr);

// Function-under-test
extern "C" void cbor_set_allocs(_cbor_malloc_t, _cbor_realloc_t, _cbor_free_t);

// Custom memory allocation functions
void* custom_malloc_17(size_t size) {
    std::cout << "Allocating " << size << " bytes" << std::endl;
    return malloc(size);
}

void* custom_realloc_17(void* ptr, size_t size) {
    std::cout << "Reallocating to " << size << " bytes" << std::endl;
    return realloc(ptr, size);
}

void custom_free_17(void* ptr) {
    std::cout << "Freeing memory" << std::endl;
    free(ptr);
}

// Fuzzing harness
extern "C" int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
    // Call the function-under-test with non-NULL function pointers
    cbor_set_allocs(custom_malloc_17, custom_realloc_17, custom_free_17);

    // Test the custom allocation functions with the provided data
    if (size > 0) {
        void* ptr = custom_malloc_17(size);
        if (ptr) {
            memcpy(ptr, data, size);
            // Simulate some processing that might use realloc
            if (size > 1) {
                ptr = custom_realloc_17(ptr, size / 2);
            }
            custom_free_17(ptr);
        }
    }

    return 0;
}