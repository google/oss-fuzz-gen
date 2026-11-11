#include <stdint.h>
#include <stddef.h>
#include <curl/curl.h>
#include <string.h>
#include <stdlib.h> // Include for malloc and free

extern "C" int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
    CURLU *url_handle = curl_url(); // Initialize a CURLU handle

    if (url_handle == NULL) {
        return 0; // If initialization fails, exit gracefully
    }

    // Convert the input data to a null-terminated string
    char *url_string = (char *)malloc(size + 1);
    if (url_string == NULL) {
        curl_url_cleanup(url_handle);
        return 0;
    }
    memcpy(url_string, data, size);
    url_string[size] = '\0';

    // Attempt to set the URL using the provided data
    CURLUcode result = curl_url_set(url_handle, CURLUPART_URL, url_string, 0);

    // Check if setting the URL was successful
    if (result == CURLUE_OK) {
        // Perform additional operations if needed
        // For example, you might want to get some parts of the URL using curl_url_get()
    }

    // Clean up
    free(url_string);
    curl_url_cleanup(url_handle);

    return 0;
}