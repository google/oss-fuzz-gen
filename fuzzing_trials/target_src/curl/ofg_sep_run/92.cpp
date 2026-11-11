#include <curl/curl.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput_92(const uint8_t *data, size_t size) {
    CURLcode result;
    curl_mimepart *part = NULL;
    char *encoder_name = NULL;
    CURL *curl = curl_easy_init();
    curl_mime *mime = curl_mime_init(curl);

    if (size == 0 || !curl || !mime) {
        curl_easy_cleanup(curl);
        return 0;
    }

    // Initialize the mime part
    part = curl_mime_addpart(mime);
    if (!part) {
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Allocate and copy the encoder name from the input data
    encoder_name = (char *)malloc(size + 1);
    if (!encoder_name) {
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }
    memcpy(encoder_name, data, size);
    encoder_name[size] = '\0';  // Null-terminate the string

    // Call the function-under-test
    result = curl_mime_encoder(part, encoder_name);

    // Clean up
    free(encoder_name);
    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    return 0;
}