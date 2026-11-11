#include <curl/curl.h>
#include <stdint.h>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput_43(const uint8_t *data, size_t size) {
    CURL *easy_handle = curl_easy_init();
    CURL *duphandle = NULL;

    if (easy_handle == NULL) {
        return 0;
    }

    // Set some options on the easy handle to ensure it's not NULL
    curl_easy_setopt(easy_handle, CURLOPT_URL, "http://example.com");
    curl_easy_setopt(easy_handle, CURLOPT_FOLLOWLOCATION, 1L);

    // Call the function-under-test
    duphandle = curl_easy_duphandle(easy_handle);

    // Clean up
    curl_easy_cleanup(easy_handle);
    if (duphandle != NULL) {
        curl_easy_cleanup(duphandle);
    }

    return 0;
}