#include <stdint.h>
#include <stddef.h>
#include <curl/curl.h>
#include <sys/select.h>

extern "C" int LLVMFuzzerTestOneInput_89(const uint8_t *data, size_t size) {
    CURLM *multi_handle;
    fd_set read_fd_set, write_fd_set, exc_fd_set;
    int max_fd;
    CURLMcode result;

    // Initialize CURL multi handle
    multi_handle = curl_multi_init();
    if (!multi_handle) {
        return 0;
    }

    // Initialize fd_sets
    FD_ZERO(&read_fd_set);
    FD_ZERO(&write_fd_set);
    FD_ZERO(&exc_fd_set);

    // Call the function-under-test
    result = curl_multi_fdset(multi_handle, &read_fd_set, &write_fd_set, &exc_fd_set, &max_fd);

    // Cleanup
    curl_multi_cleanup(multi_handle);

    return 0;
}