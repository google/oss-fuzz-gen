#include <stdint.h>
#include <stddef.h>
#include <curl/curl.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_41(const uint8_t *data, size_t size) {
    CURL *curl = curl_easy_init();
    if (!curl || size == 0) {
        return 0;
    }

    // Initialize a curl_mime structure
    curl_mime *mime = curl_mime_init(curl);
    if (!mime) {
        curl_easy_cleanup(curl);
        return 0;
    }

    // Add a part to the mime structure
    curl_mimepart *part = curl_mime_addpart(mime);
    if (!part) {
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Convert the input data to a null-terminated string for the filename
    char *filename = new char[size + 1];
    memcpy(filename, data, size);
    filename[size] = '\0';

    // Call the function-under-test
    CURLcode res = curl_mime_filename(part, filename);

    // Clean up
    delete[] filename;
    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    return 0;
}