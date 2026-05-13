#include <stdint.h>
#include <stddef.h>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_98(const uint8_t *data, size_t size) {
    CURLM *multi_handle;
    CURLMcode res;
    
    // Initialize a CURLM handle
    multi_handle = curl_multi_init();
    if (!multi_handle) {
        return 0;
    }

    // Ensure we have enough data to extract CURLMoption and a pointer
    if (size < sizeof(CURLMoption) + sizeof(void *)) {
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Extract CURLMoption from the data
    CURLMoption option = *(reinterpret_cast<const CURLMoption *>(data));
    data += sizeof(CURLMoption);
    size -= sizeof(CURLMoption);

    // Extract a pointer from the data (cast to void*)
    void *ptr = nullptr;
    if (size >= sizeof(void *)) {
        ptr = *(reinterpret_cast<void * const *>(data));
    }

    // Call the function-under-test
    res = curl_multi_setopt(multi_handle, option, ptr);

    // Clean up
    curl_multi_cleanup(multi_handle);

    return 0;
}