#include <stdint.h>
#include <stdlib.h>
#include <string.h>  // Include for memcpy
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_10(const uint8_t *data, size_t size) {
    CURLU *url = curl_url();  // Initialize a CURLU object
    if (url == NULL) {
        return 0;  // Return if initialization fails
    }

    // Attempt to set the URL with the input data
    // This is a dummy operation to use the input data
    char *url_data = (char *)malloc(size + 1);
    if (url_data == NULL) {
        curl_url_cleanup(url);
        return 0;
    }

    memcpy(url_data, data, size);
    url_data[size] = '\0';  // Null-terminate the string

    // Use the input data to set a URL, ignoring the result
    curl_url_set(url, CURLUPART_URL, url_data, 0);

    // Clean up the CURLU object
    curl_url_cleanup(url);

    free(url_data);  // Free the allocated memory

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

    LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
