#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

extern "C" {
    #include <stdint.h> // Include the header for uint8_t
}

extern "C" {
    int LLVMFuzzerTestOneInput_100(const uint8_t *data, size_t size) {
        CURLU *url_handle = NULL;
        CURLUcode result;
        char *output = NULL;
        CURLUPart part;
        unsigned int flags = 0;

        // Initialize CURLU handle
        url_handle = curl_url();

        if (url_handle == NULL) {
            return 0;
        }

        // Create a null-terminated string from input data
        char *url_string = (char *)malloc(size + 1);
        if (url_string == NULL) {
            curl_url_cleanup(url_handle);
            return 0;
        }
        memcpy(url_string, data, size);
        url_string[size] = '\0';

        // Set the URL in the CURLU handle
        result = curl_url_set(url_handle, CURLUPART_URL, url_string, 0);
        free(url_string);

        if (result != CURLUE_OK) {
            curl_url_cleanup(url_handle);
            return 0;
        }

        // Fuzz different parts of the URL
        for (int i = CURLUPART_URL; i <= CURLUPART_ZONEID; i++) {
            part = static_cast<CURLUPart>(i);
            result = curl_url_get(url_handle, part, &output, flags);

            if (result == CURLUE_OK && output != NULL) {
                // Use the output for further processing if needed
                // For now, just free the output
                curl_free(output);
            }
        }

        // Clean up
        curl_url_cleanup(url_handle);

        return 0;
    }
}