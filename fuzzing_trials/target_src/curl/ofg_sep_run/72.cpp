#include <curl/curl.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput_72(const uint8_t *data, size_t size) {
    if (size < sizeof(CURLoption)) {
        return 0; // Not enough data to determine a CURLoption
    }

    // Initialize a CURL handle
    CURL *curl = curl_easy_init();
    if (!curl) {
        return 0;
    }

    // Extract a CURLoption from the input data
    CURLoption option = *(CURLoption *)data;
    data += sizeof(CURLoption);
    size -= sizeof(CURLoption);

    // Prepare a non-NULL pointer to pass as the third argument
    void *parameter = (void *)data;

    // Call the function-under-test
    curl_easy_setopt(curl, option, parameter);

    // Cleanup
    curl_easy_cleanup(curl);

    return 0;
}