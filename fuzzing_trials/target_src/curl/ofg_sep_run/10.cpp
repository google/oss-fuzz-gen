#include <stdint.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_10(const uint8_t *data, size_t size) {
    // Initialize CURL library
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Call the function-under-test
    CURLU *url_handle = curl_url();

    if (url_handle != NULL && size > 0) {
        // Convert the input data to a null-terminated string
        char *input_data = (char *)malloc(size + 1);
        if (input_data != NULL) {
            memcpy(input_data, data, size);
            input_data[size] = '\0';

            // Set the URL using the input data
            curl_url_set(url_handle, CURLUPART_URL, input_data, 0);

            // Free the allocated string
            free(input_data);
        }

        // Cleanup
        curl_url_cleanup(url_handle);
    }

    // Cleanup CURL library
    curl_global_cleanup();

    return 0;
}