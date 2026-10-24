#include <curl/curl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_139(const uint8_t *data, size_t size) {
    CURLM *multi_handle = NULL;
    CURL *easy_handle = NULL;
    CURLMcode result;

    // Initialize CURL globally
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        return 0;
    }

    // Initialize a multi handle
    multi_handle = curl_multi_init();
    if (!multi_handle) {
        curl_global_cleanup();
        return 0;
    }

    // Initialize an easy handle
    easy_handle = curl_easy_init();
    if (!easy_handle) {
        curl_multi_cleanup(multi_handle);
        curl_global_cleanup();
        return 0;
    }

    // Create a temporary file to store the input data
    FILE *temp_file = tmpfile();
    if (!temp_file) {
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        curl_global_cleanup();
        return 0;
    }

    // Write the input data to the temporary file
    fwrite(data, 1, size, temp_file);
    rewind(temp_file);

    // Set the URL and the file as the input to the easy handle
    curl_easy_setopt(easy_handle, CURLOPT_URL, "http://example.com");
    curl_easy_setopt(easy_handle, CURLOPT_READDATA, temp_file);
    curl_easy_setopt(easy_handle, CURLOPT_UPLOAD, 1L);

    // Add the easy handle to the multi handle
    result = curl_multi_add_handle(multi_handle, easy_handle);

    // Perform the request
    int still_running = 0;
    curl_multi_perform(multi_handle, &still_running);

    // Clean up
    curl_multi_remove_handle(multi_handle, easy_handle);
    curl_easy_cleanup(easy_handle);
    curl_multi_cleanup(multi_handle);
    curl_global_cleanup();
    fclose(temp_file);

    return 0;
}