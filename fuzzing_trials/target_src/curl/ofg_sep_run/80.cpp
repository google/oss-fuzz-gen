#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_80(const uint8_t *data, size_t size) {
    struct curl_httppost *formpost = NULL;
    struct curl_httppost *lastptr = NULL;
    
    if (size < 1) {
        return 0;
    }

    // Create a form with some dummy data
    curl_formadd(&formpost, &lastptr,
                 CURLFORM_COPYNAME, "name",
                 CURLFORM_COPYCONTENTS, "content",
                 CURLFORM_END);

    // Call the function-under-test
    curl_formfree(formpost);

    return 0;
}