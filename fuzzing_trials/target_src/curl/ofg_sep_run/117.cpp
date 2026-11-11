#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdio>

extern "C" {
    #include <curl/curl.h>
}

extern "C" int LLVMFuzzerTestOneInput_117(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to split into two strings and a size_t
    if (size < 3) return 0;

    // Calculate lengths for the two strings
    size_t str1_len = size / 3;
    size_t str2_len = size / 3;
    size_t compare_len = size - str1_len - str2_len;

    // Allocate and initialize the first string
    char *str1 = new char[str1_len + 1];
    memcpy(str1, data, str1_len);
    str1[str1_len] = '\0';

    // Allocate and initialize the second string
    char *str2 = new char[str2_len + 1];
    memcpy(str2, data + str1_len, str2_len);
    str2[str2_len] = '\0';

    // Use the remaining bytes to determine the number of characters to compare
    size_t n = compare_len;

    // Call the function-under-test
    int result = curl_strnequal(str1, str2, n);

    // Print the result for debugging purposes (optional)
    printf("Result of curl_strnequal: %d\n", result);

    // Clean up
    delete[] str1;
    delete[] str2;

    return 0;
}