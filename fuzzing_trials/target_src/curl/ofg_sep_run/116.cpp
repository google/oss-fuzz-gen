#include <cstddef>
#include <cstring>
#include <cstdint>
#include <cstdio>

extern "C" {
    #include <curl/curl.h>
}

extern "C" int LLVMFuzzerTestOneInput_116(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0;
    }

    // Split the input data into two parts for the two strings
    size_t mid = size / 2;

    // Ensure null-terminated strings
    char *str1 = new char[mid + 1];
    char *str2 = new char[size - mid + 1];

    memcpy(str1, data, mid);
    memcpy(str2, data + mid, size - mid);

    str1[mid] = '\0';
    str2[size - mid] = '\0';

    // Call the function-under-test
    int result = curl_strnequal(str1, str2, mid);

    // Clean up
    delete[] str1;
    delete[] str2;

    return 0;
}