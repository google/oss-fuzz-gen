#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>  // Include for uint8_t
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_99(const uint8_t *data, size_t size) {
    CURLU *url = curl_url();
    CURLUcode result;
    char *part = NULL;

    if (url == NULL || size == 0) {
        return 0;
    }

    // Create a null-terminated string from the data
    char *url_string = (char *)malloc(size + 1);
    if (url_string == NULL) {
        curl_url_cleanup(url);
        return 0;
    }
    memcpy(url_string, data, size);
    url_string[size] = '\0';

    // Set the URL to the CURLU object
    curl_url_set(url, CURLUPART_URL, url_string, 0);

    // Try to get different parts of the URL
    result = curl_url_get(url, CURLUPART_SCHEME, &part, 0);
    if (result == CURLUE_OK) {
        curl_free(part);
    }

    result = curl_url_get(url, CURLUPART_HOST, &part, 0);
    if (result == CURLUE_OK) {
        curl_free(part);
    }

    result = curl_url_get(url, CURLUPART_PATH, &part, 0);
    if (result == CURLUE_OK) {
        curl_free(part);
    }

    // Clean up
    free(url_string);
    curl_url_cleanup(url);

    return 0;
}