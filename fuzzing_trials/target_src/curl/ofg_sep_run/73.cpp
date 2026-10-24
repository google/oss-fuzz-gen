#include <curl/curl.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <string>

// Function to create a valid URL from fuzz data
std::string createValidURL(const uint8_t *data, size_t size) {
    std::string url = "http://example.com/";
    for (size_t i = 0; i < size; ++i) {
        // Append each byte as a character to the URL path
        url += static_cast<char>(data[i] % 26 + 'a');
    }
    return url;
}

extern "C" int LLVMFuzzerTestOneInput_73(const uint8_t *data, size_t size) {
    // Initialize a CURL handle
    CURL *curl = curl_easy_init();
    if (!curl) {
        return 0;
    }

    // Ensure the data size is sufficient for setting options
    if (size < sizeof(long) + 1) {
        curl_easy_cleanup(curl);
        return 0;
    }

    // Use the first byte of data to determine the CURLoption
    CURLoption option = static_cast<CURLoption>(data[0] % 4);

    // Use the rest of the data as the option value
    void *value = nullptr;
    std::string url;

    switch (option) {
        case CURLOPT_URL:
            // Create a valid URL from the data
            url = createValidURL(data + 1, size - 1);
            value = static_cast<void *>(strdup(url.c_str()));
            if (value) {
                curl_easy_setopt(curl, CURLOPT_URL, value);
            }
            break;
        case CURLOPT_TIMEOUT:
            // Use a long value for timeout
            value = static_cast<void *>(new long(*reinterpret_cast<const long *>(data + 1) % 100));
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, *static_cast<long *>(value));
            break;
        case CURLOPT_VERBOSE:
            // Use a long value for verbose (0 or 1)
            value = static_cast<void *>(new long(data[1] % 2));
            curl_easy_setopt(curl, CURLOPT_VERBOSE, *static_cast<long *>(value));
            break;
        case CURLOPT_FOLLOWLOCATION:
            // Use a long value for follow location (0 or 1)
            value = static_cast<void *>(new long(data[1] % 2));
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, *static_cast<long *>(value));
            break;
        default:
            curl_easy_cleanup(curl);
            return 0;
    }

    // Perform a simple HTTP GET request to increase code coverage
    if (option == CURLOPT_URL && value) {
        CURLcode res = curl_easy_perform(curl);
        // Check for errors
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }
    }

    // Clean up
    if (option == CURLOPT_URL && value) {
        free(value);
    } else {
        delete static_cast<long *>(value);
    }
    curl_easy_cleanup(curl);

    return 0;
}