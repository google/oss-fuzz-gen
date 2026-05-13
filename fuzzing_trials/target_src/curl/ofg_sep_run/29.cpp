#include <stdint.h>
#include <stddef.h>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_29(const uint8_t *data, size_t size) {
    // Initialize CURLM handle
    CURLM *multi_handle = curl_multi_init();
    if (multi_handle == NULL) {
        return 0; // Failed to initialize CURLM, exit early
    }

    // Ensure size is sufficient to extract a socket value
    if (size < sizeof(curl_socket_t)) {
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Extract a curl_socket_t from the input data
    curl_socket_t sockfd = *(const curl_socket_t *)data;

    // Use the remaining data as a pointer value
    void *ptr = (void *)(data + sizeof(curl_socket_t));

    // Call the function-under-test
    CURLMcode result = curl_multi_assign(multi_handle, sockfd, ptr);

    // Cleanup CURLM handle
    curl_multi_cleanup(multi_handle);

    return 0;
}