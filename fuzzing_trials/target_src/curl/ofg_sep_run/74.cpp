#include <curl/curl.h>
#include <stdint.h>
#include <stddef.h>
#include <string>

// Function to write received data to a string (used as a callback)
size_t WriteCallback_74(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

extern "C" int LLVMFuzzerTestOneInput_74(const uint8_t *data, size_t size) {
    CURLM *multi_handle;
    CURL *easy_handle;
    CURLMcode mcode;
    CURLcode ecode;
    std::string readBuffer;

    // Initialize a CURLM handle
    multi_handle = curl_multi_init();
    if (multi_handle == NULL) {
        return 0; // If initialization fails, return early
    }

    // Initialize a CURL easy handle
    easy_handle = curl_easy_init();
    if (easy_handle == NULL) {
        curl_multi_cleanup(multi_handle);
        return 0; // If initialization fails, return early
    }

    // Convert input data to a string and use it as a URL (ensure it's null-terminated)
    std::string url(reinterpret_cast<const char*>(data), size);
    url.push_back('\0');

    // Set the URL for the easy handle
    curl_easy_setopt(easy_handle, CURLOPT_URL, url.c_str());

    // Set the write callback function
    curl_easy_setopt(easy_handle, CURLOPT_WRITEFUNCTION, WriteCallback_74);
    curl_easy_setopt(easy_handle, CURLOPT_WRITEDATA, &readBuffer);

    // Add the easy handle to the multi handle
    mcode = curl_multi_add_handle(multi_handle, easy_handle);
    if (mcode != CURLM_OK) {
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Perform the request
    int still_running;
    do {
        mcode = curl_multi_perform(multi_handle, &still_running);
    } while (mcode == CURLM_OK && still_running);

    // Cleanup
    curl_multi_remove_handle(multi_handle, easy_handle);
    curl_easy_cleanup(easy_handle);
    curl_multi_cleanup(multi_handle);

    return 0;
}