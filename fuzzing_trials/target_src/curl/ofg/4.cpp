#include <stdint.h>
#include <stdlib.h>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    CURLU *url = curl_url();  // Initialize a CURLU object
    CURLUcode rc;

    if (url == NULL || size == 0) {
        return 0;  // Exit if initialization failed or input size is zero
    }

    // Attempt to set the URL using the provided data
    rc = curl_url_set(url, CURLUPART_URL, (const char *)data, 0);

    if (rc == CURLUE_OK) {
        // Duplicate the CURLU object if the URL was set successfully
        CURLU *dup_url = curl_url_dup(url);
        if (dup_url != NULL) {
            curl_url_cleanup(dup_url);  // Clean up the duplicated URL object
        }
    }

    curl_url_cleanup(url);  // Clean up the original URL object
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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
