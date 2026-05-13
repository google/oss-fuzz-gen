#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_113(const uint8_t *data, size_t size) {
    // Ensure that the input data is not empty
    if (size == 0) {
        return 0;
    }

    // Convert the input data to a null-terminated string
    char *inputString = new char[size + 1];
    memcpy(inputString, data, size);
    inputString[size] = '\0';

    // Initialize a curl_slist pointer
    struct curl_slist *list = NULL;

    // Call the function-under-test
    list = curl_slist_append(list, inputString);

    // Clean up
    curl_slist_free_all(list);
    delete[] inputString;

    return 0;
}