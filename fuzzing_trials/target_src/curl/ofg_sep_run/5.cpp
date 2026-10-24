#include <curl/curl.h>
#include <stdint.h>
#include <stddef.h>

extern "C" {
    struct curl_header * curl_easy_nextheader(CURL *, unsigned int, int, struct curl_header *);
}

extern "C" int LLVMFuzzerTestOneInput_5(const uint8_t *data, size_t size) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        return 0;
    }

    unsigned int header_type = 0;
    int part = 0;
    struct curl_header *prev_header = nullptr;

    // Fuzz the curl_easy_nextheader function
    struct curl_header *header = curl_easy_nextheader(curl, header_type, part, prev_header);

    // Clean up
    curl_easy_cleanup(curl);

    return 0;
}