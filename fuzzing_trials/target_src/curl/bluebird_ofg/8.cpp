#include <sys/stat.h>
#include <string.h>
#include <cstddef>
#include <cstdint>
#include <cstring> // For memcpy
#include "curl/curl.h"

extern "C" int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    CURLU *original_url = curl_url();  // Create a new CURLU object
    CURLUcode result;
    
    // If the input data is large enough, use it to set a URL in the CURLU object
    if (size > 0) {
        // Create a null-terminated string from the input data
        char *url_string = new char[size + 1];
        memcpy(url_string, data, size);
        url_string[size] = '\0';

        // Set the URL in the CURLU object
        result = curl_url_set(original_url, CURLUPART_URL, url_string, 0);

        delete[] url_string;
        
        if (result != CURLUE_OK) {
            curl_url_cleanup(original_url);
            return 0;
        }
    }

    // Duplicate the CURLU object
    CURLU *duplicated_url = curl_url_dup(original_url);

    // Clean up
    curl_url_cleanup(original_url);
    if (duplicated_url != NULL) {
        curl_url_cleanup(duplicated_url);
    }

    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
