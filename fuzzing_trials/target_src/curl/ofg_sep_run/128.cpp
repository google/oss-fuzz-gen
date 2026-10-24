extern "C" {
#include <curl/curl.h>
#include <stdint.h>  // For uint8_t
#include <stddef.h>  // For size_t
}

extern "C" int LLVMFuzzerTestOneInput_128(const uint8_t *data, size_t size) {
    // Initialize CURLSH and CURLSHcode
    CURLSH *share_handle = curl_share_init();
    CURLSHcode result;

    // Ensure the data size is sufficient for setting options
    if (size < 2) {  // Ensure there's at least one byte for the option and one for data
        curl_share_cleanup(share_handle);
        return 0;
    }

    // Extract a CURLSHoption from the input data
    CURLSHoption option = static_cast<CURLSHoption>(data[0] % CURLSHOPT_LAST);

    // Use a non-NULL pointer for the third parameter
    void *ptr = nullptr;

    // Depending on the option, set ptr to a valid value
    if (option == CURLSHOPT_SHARE || option == CURLSHOPT_UNSHARE) {
        // Use a valid CURL lock data type
        ptr = (void *)(data[1] % CURL_LOCK_DATA_LAST);
    } else {
        // Default to some valid non-NULL pointer
        ptr = (void *)(data + 1);
    }

    // Call the function-under-test
    result = curl_share_setopt(share_handle, option, ptr);

    // Clean up the CURL share handle
    curl_share_cleanup(share_handle);

    return 0;
}