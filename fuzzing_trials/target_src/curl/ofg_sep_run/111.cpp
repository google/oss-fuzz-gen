#include <stdint.h>
#include <stddef.h>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_111(const uint8_t *data, size_t size) {
    // Initialize the parameter for curl_global_init
    long flags = CURL_GLOBAL_DEFAULT;

    // Call the function-under-test
    CURLcode result = curl_global_init(flags);

    // Check the result (though for fuzzing, we mainly care about calling the function)
    if (result != CURLE_OK) {
        // Handle error if necessary
    }

    // Normally, you would clean up with curl_global_cleanup(), but since this is a fuzzing harness,
    // and curl_global_cleanup() is not thread-safe or reentrant, it is typically not called here.

    return 0;
}