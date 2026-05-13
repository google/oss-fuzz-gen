#include <stdint.h>
#include <stddef.h>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t *data, size_t size) {
    // Ensure that the data size is sufficient to form a CURLUcode.
    if (size < sizeof(CURLUcode)) {
        return 0;
    }

    // Interpret the first bytes of data as a CURLUcode.
    CURLUcode code = *(reinterpret_cast<const CURLUcode*>(data));

    // Call the function-under-test.
    const char *result = curl_url_strerror(code);

    // Use the result to avoid unused variable warning.
    if (result) {
        // Do something trivial with the result, like checking its length.
        size_t length = 0;
        while (result[length] != '\0') {
            length++;
        }
    }

    return 0;
}