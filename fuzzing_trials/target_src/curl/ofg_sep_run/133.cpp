#include <curl/curl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_133(const uint8_t *data, size_t size) {
    CURL *curl;
    CURLcode res;
    const char *ssl_backend = "openssl"; // Example SSL backend
    const unsigned char *ssl_cert = data;
    const unsigned char *ssl_key = data;
    size_t cert_size = size / 2;
    size_t key_size = size - cert_size;

    // Initialize CURL
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (!curl) {
        curl_global_cleanup();
        return 0;
    }

    // Call the function-under-test
    res = curl_easy_ssls_import(curl, ssl_backend, ssl_cert, cert_size, ssl_key, key_size);

    // Cleanup
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    return 0;
}