#include <cstddef>
#include <cstdint>
#include <cstring>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_112(const uint8_t *data, size_t size) {
    // Create a null-terminated string from the input data
    char *inputString = new char[size + 1];
    memcpy(inputString, data, size);
    inputString[size] = '\0';

    // Initialize a curl_slist
    struct curl_slist *slist = nullptr;

    // Call the function-under-test
    slist = curl_slist_append(slist, inputString);

    // Clean up
    curl_slist_free_all(slist);
    delete[] inputString;

    return 0;
}