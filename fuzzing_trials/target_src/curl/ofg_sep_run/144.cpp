#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_144(const uint8_t *data, size_t size) {
    // Declare and initialize a curl_slist pointer
    struct curl_slist *slist = NULL;

    // Ensure size is not zero to avoid unnecessary operations
    if (size > 0) {
        // Allocate memory for a string from the fuzzing data
        char *str = (char *)malloc(size + 1);
        if (str != NULL) {
            // Copy the fuzzing data into the string and null-terminate it
            memcpy(str, data, size);
            str[size] = '\0';

            // Append the string to the curl_slist
            slist = curl_slist_append(slist, str);

            // Free the allocated string memory
            free(str);
        }
    }

    // Call the function-under-test
    curl_slist_free_all(slist);

    return 0;
}