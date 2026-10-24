#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_101(const uint8_t *data, size_t size) {
    // Initialize CURLU pointer
    CURLU *url = curl_url();
    if (url == NULL) {
        return 0;
    }

    // Convert input data to a null-terminated string
    char *url_string = (char *)malloc(size + 1);
    if (url_string == NULL) {
        curl_url_cleanup(url);
        return 0;
    }
    memcpy(url_string, data, size);
    url_string[size] = '\0';

    // Set the URL in the CURLU object
    CURLUcode uc = curl_url_set(url, CURLUPART_URL, url_string, 0);
    free(url_string);

    if (uc != CURLUE_OK) {
        curl_url_cleanup(url);
        return 0;
    }

    // Call the function-under-test
    CURLU *url_dup = curl_url_dup(url);

    // Clean up
    curl_url_cleanup(url);
    if (url_dup != NULL) {
        curl_url_cleanup(url_dup);
    }

    return 0;
}