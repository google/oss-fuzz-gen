#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "curl/curl.h"

extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t *data, size_t size) {
    // Initialize CURLU object
    CURLU *url = curl_url();
    if (!url) {
        return 0;
    }

    // Create a null-terminated string from the input data
    char *url_string = (char *)malloc(size + 1);
    if (!url_string) {
        curl_url_cleanup(url);
        return 0;
    }
    memcpy(url_string, data, size);
    url_string[size] = '\0';

    // Set the URL
    CURLUcode set_result = curl_url_set(url, CURLUPART_URL, url_string, 0);
    free(url_string);
    if (set_result != CURLUE_OK) {
        curl_url_cleanup(url);
        return 0;
    }

    // Prepare to get a part of the URL
    char *output = NULL;
    CURLUPart part = CURLUPART_HOST; // Example part to retrieve
    unsigned int flags = 0; // Example flags

    // Call the function-under-test
    CURLUcode get_result = curl_url_get(url, part, &output, flags);

    // Clean up
    if (output) {
        curl_free(output);
    }
    curl_url_cleanup(url);

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

    LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
