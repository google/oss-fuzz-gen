#include <curl/curl.h>
#include <stdint.h>
#include <stddef.h>
#include <cstring> // Include this header for memcpy

extern "C" int LLVMFuzzerTestOneInput_96(const uint8_t *data, size_t size) {
    // Initialize a CURL handle
    CURL *curl_handle = curl_easy_init();
    if (curl_handle == NULL) {
        return 0; // If initialization fails, exit early
    }

    // Set some options for the CURL handle using the fuzzing data
    // Here, we only set options if the size is sufficient
    if (size > 0) {
        // Use the fuzzing data to set a URL as an example
        // Ensure null-termination for safety
        char url_buffer[256];
        size_t copy_size = size < 255 ? size : 255;
        memcpy(url_buffer, data, copy_size);
        url_buffer[copy_size] = '\0';

        // Set the URL option
        curl_easy_setopt(curl_handle, CURLOPT_URL, url_buffer);
    }

    // Call the function-under-test
    curl_easy_cleanup(curl_handle);

    return 0;
}