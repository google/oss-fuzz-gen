#include <curl/curl.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  // Include for mkstemp, write, close, unlink

extern "C" int LLVMFuzzerTestOneInput_137(const uint8_t *data, size_t size) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        return 0;
    }

    curl_mime *mime = curl_mime_init(curl);
    if (!mime) {
        curl_easy_cleanup(curl);
        return 0;
    }

    curl_mimepart *part = curl_mime_addpart(mime);
    if (!part) {
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Create a temporary file to store the fuzz data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpl);
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }

    close(fd);

    // Call the function under test
    CURLcode result = curl_mime_filedata(part, tmpl);

    // Clean up
    unlink(tmpl);
    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    return 0;
}