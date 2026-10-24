#include <cstdint>
#include <curl/curl.h>
#include <cstring>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput_28(const uint8_t *data, size_t size) {
    if (size < sizeof(curl_socket_t)) {
        return 0; // Not enough data to derive a socket value
    }

    CURLM *multi_handle = curl_multi_init();
    if (!multi_handle) {
        return 0;
    }

    // Derive a socket value from the input data
    curl_socket_t sockfd;
    memcpy(&sockfd, data, sizeof(curl_socket_t));

    // Ensure the rest of the data is null-terminated for safety
    size_t userp_size = size - sizeof(curl_socket_t);
    char *userp = new char[userp_size + 1];
    memcpy(userp, data + sizeof(curl_socket_t), userp_size);
    userp[userp_size] = '\0';

    // Call the function-under-test
    CURLMcode result = curl_multi_assign(multi_handle, sockfd, userp);

    // Check the result to ensure the function was invoked correctly
    if (result != CURLM_OK) {
        // Handle error case
    }

    // Clean up
    delete[] userp;
    curl_multi_cleanup(multi_handle);

    return 0;
}