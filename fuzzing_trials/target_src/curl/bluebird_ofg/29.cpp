#include <sys/stat.h>
#include <string.h>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include "curl/curl.h"

extern "C" int LLVMFuzzerTestOneInput_29(const uint8_t *data, size_t size) {
    // Initialize CURLU handle
    CURLU *url_handle = curl_url();
    if (url_handle == NULL) {
        return 0;
    }

    // Ensure data is null-terminated for URL operations
    char *url_data = (char *)malloc(size + 1);
    if (url_data == NULL) {
        curl_url_cleanup(url_handle);
        return 0;
    }
    memcpy(url_data, data, size);
    url_data[size] = '\0';

    // Set URL to the CURLU handle
    CURLUcode set_result = curl_url_set(url_handle, CURLUPART_URL, url_data, 0);
    if (set_result != CURLUE_OK) {
        free(url_data);
        curl_url_cleanup(url_handle);
        return 0;
    }

    // Prepare to get a part of the URL

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from curl_url_set to curl_multi_add_handle
    // Ensure dataflow is valid (i.e., non-null)
    if (!url_handle) {
    	return 0;
    }
    CURLMcode ret_curl_multi_add_handle_bovni = curl_multi_add_handle(NULL, (void *)url_handle);
    // End mutation: Producer.APPEND_MUTATOR
    
    char *url_part = NULL;
    CURLUPart part = CURLUPART_SCHEME; // Example part, can try other parts as well

    // Call the function-under-test
    CURLUcode result = curl_url_get(url_handle, part, &url_part, 0);

    // Clean up
    if (url_part != NULL) {
        curl_free(url_part);
    }
    free(url_data);
    curl_url_cleanup(url_handle);

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

    LLVMFuzzerTestOneInput_29(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
