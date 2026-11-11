#include <cstddef>
#include <cstdint>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_126(const uint8_t *data, size_t size) {
    // Initialize the curl library
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Define and initialize the parameters for curl_global_sslset
    curl_sslbackend backend = CURLSSLBACKEND_OPENSSL; // Example backend
    const char *str = "openssl"; // Example string for SSL backend
    const curl_ssl_backend **avail_backends = nullptr;

    // Call the function-under-test
    CURLsslset result = curl_global_sslset(backend, str, &avail_backends);

    // Clean up
    curl_global_cleanup();

    return 0;
}