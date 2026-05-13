#include <curl/curl.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

extern "C" {
    const struct curl_ws_frame *curl_ws_meta(CURL *);
}

extern "C" int LLVMFuzzerTestOneInput_105(const uint8_t *data, size_t size) {
    CURL *curl = curl_easy_init();
    if (curl == NULL) {
        return 0;
    }

    // Convert the input data to a string URL if possible
    char url[256] = {0};
    if (size > 0 && size < sizeof(url)) {
        memcpy(url, data, size);
        url[size] = '\0';  // Ensure null-termination
    } else {
        strncpy(url, "http://example.com", sizeof(url) - 1);
    }

    // Set the URL option for the CURL handle using the input data
    curl_easy_setopt(curl, CURLOPT_URL, url);

    // Perform the request to ensure the CURL handle is properly initialized
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        return 0;
    }

    // Call the function-under-test
    const struct curl_ws_frame *frame = curl_ws_meta(curl);

    // Check if the frame is not null to ensure the function is being tested effectively
    if (frame != NULL) {
        // Process the frame if needed
    }

    // Cleanup
    curl_easy_cleanup(curl);

    return 0;
}