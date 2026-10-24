#include <curl/curl.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

extern "C" {
    #include <curl/curl.h>  // Ensure that C functions are correctly linked
}

extern "C" int LLVMFuzzerTestOneInput_93(const uint8_t *data, size_t size) {
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;
    
    // Initialize CURL
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (!curl) {
        curl_global_cleanup();
        return 0;
    }

    // Ensure that data is null-terminated for string operations
    char *header_name = (char *)malloc(size + 1);
    if (!header_name) {
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return 0;
    }
    memcpy(header_name, data, size);
    header_name[size] = '\0';

    // Add the header
    headers = curl_slist_append(headers, header_name);

    // Set the headers for the CURL request
    res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // Perform a simple request to ensure the headers are processed
    if (res == CURLE_OK) {
        res = curl_easy_perform(curl);
    }

    // Clean up
    curl_slist_free_all(headers);
    free(header_name);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    
    return 0;
}