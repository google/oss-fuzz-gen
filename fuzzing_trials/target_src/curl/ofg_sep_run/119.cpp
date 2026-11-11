#include <curl/curl.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h> // Include for strlen and memcpy

extern "C" {

// Custom memory allocation functions
void* my_malloc_119(size_t size) {
    return malloc(size);
}

void my_free_119(void* ptr) {
    free(ptr);
}

void* my_realloc_119(void* ptr, size_t size) {
    return realloc(ptr, size);
}

char* my_strdup_119(const char* str) {
    if (str == NULL) return NULL;
    size_t len = strlen(str) + 1;
    char* copy = (char*)malloc(len);
    if (copy) {
        memcpy(copy, str, len);
    }
    return copy;
}

void* my_calloc_119(size_t nmemb, size_t size) {
    return calloc(nmemb, size);
}

int LLVMFuzzerTestOneInput_119(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for a long value
    if (size < sizeof(long)) {
        return 0;
    }

    // Extract a long value from the data
    long flag = *(const long*)data;

    // Call the function-under-test
    CURLcode result = curl_global_init_mem(flag, my_malloc_119, my_free_119, my_realloc_119, my_strdup_119, my_calloc_119);

    // Perform any necessary cleanup
    if (result == CURLE_OK) {
        curl_global_cleanup();
    }

    return 0;
}

}