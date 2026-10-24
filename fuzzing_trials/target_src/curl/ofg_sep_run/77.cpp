#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_77(const uint8_t *data, size_t size) {
    CURLU *url_handle = curl_url();
    if (url_handle == NULL) {
        return 0;
    }

    // Ensure data is null-terminated for use as a string
    char *url_part = (char *)malloc(size + 1);
    if (url_part == NULL) {
        curl_url_cleanup(url_handle);
        return 0;
    }
    memcpy(url_part, data, size);
    url_part[size] = '\0';

    // Try different CURLUPart values
    CURLUPart parts[] = {CURLUPART_URL, CURLUPART_SCHEME, CURLUPART_HOST, CURLUPART_PORT, CURLUPART_PATH, CURLUPART_QUERY, CURLUPART_FRAGMENT, CURLUPART_USER, CURLUPART_PASSWORD, CURLUPART_OPTIONS};
    unsigned int options = 0; // No specific options for now

    for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); ++i) {
        curl_url_set(url_handle, parts[i], url_part, options);
    }

    free(url_part);
    curl_url_cleanup(url_handle);
    return 0;
}