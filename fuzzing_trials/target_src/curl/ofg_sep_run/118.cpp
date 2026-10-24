#include <curl/curl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include for strlen and memcpy

extern "C" {

// Custom memory allocation functions
void* my_malloc_118(size_t size) {
    return malloc(size);
}

void my_free_118(void* ptr) {
    free(ptr);
}

void* my_realloc_118(void* ptr, size_t size) {
    return realloc(ptr, size);
}

char* my_strdup_118(const char* str) {
    size_t len = strlen(str) + 1;
    char* copy = (char*)malloc(len);
    if (copy) {
        memcpy(copy, str, len);
    }
    return copy;
}

void* my_calloc_118(size_t nmemb, size_t size) {
    return calloc(nmemb, size);
}

int LLVMFuzzerTestOneInput_118(const uint8_t *data, size_t size) {
    // Ensure the data is large enough to extract a long value
    if (size < sizeof(long)) {
        return 0;
    }

    // Extract a long value from the input data
    long flags = *(const long*)data;

    // Call the function-under-test
    CURLcode result = curl_global_init_mem(flags, my_malloc_118, my_free_118, my_realloc_118, my_strdup_118, my_calloc_118);

    // Clean up if initialization was successful
    if (result == CURLE_OK) {
        curl_global_cleanup();
    }

    return 0;
}

}