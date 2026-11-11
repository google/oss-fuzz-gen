#include <curl/curl.h>
#include <stdint.h>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput_127(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0; // Not enough data to proceed
    }

    // Initialize variables
    curl_sslbackend backend = static_cast<curl_sslbackend>(data[0]); // Use data to select backend
    const char *str = reinterpret_cast<const char*>(data); // Use data as input string
    const curl_ssl_backend **backends = nullptr; // Pointer to SSL backends

    // Call the function-under-test
    CURLsslset result = curl_global_sslset(backend, str, &backends);

    // Use the result for further logic if needed (here we just return 0)
    return 0;
}