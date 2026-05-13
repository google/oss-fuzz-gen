#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_145(const uint8_t *data, size_t size) {
    struct curl_slist *slist = NULL;
    struct curl_slist *temp = NULL;

    // Ensure the data is null-terminated and not empty
    if (size > 0) {
        char *input = (char *)malloc(size + 1);
        if (input == NULL) {
            return 0;
        }
        memcpy(input, data, size);
        input[size] = '\0';

        // Add the input string to the list
        temp = curl_slist_append(slist, input);
        if (temp != NULL) {
            slist = temp;
        }

        free(input);
    }

    // Call the function-under-test
    curl_slist_free_all(slist);

    return 0;
}