#include <curl/curl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_94(const uint8_t *data, size_t size) {
    CURL *curl;
    const char *header_name;
    size_t header_name_len;
    unsigned int origin;
    int request;
    struct curl_header *header = NULL;

    // Initialize CURL
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (!curl) {
        curl_global_cleanup();
        return 0;
    }

    // Ensure the data is large enough to split into meaningful segments
    if (size < 5) {
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return 0;
    }

    // Set up the header name
    header_name_len = data[0] % (size - 4); // Ensure header_name_len is within bounds
    header_name = (const char *)(data + 1);

    // Set up the origin and request
    origin = data[header_name_len + 1];
    request = data[header_name_len + 2];

    // Call the function-under-test
    curl_easy_header(curl, header_name, header_name_len, origin, request, &header);

    // Clean up
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    return 0;
}