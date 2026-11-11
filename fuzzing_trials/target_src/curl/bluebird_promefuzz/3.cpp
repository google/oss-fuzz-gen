#include <string.h>
#include <sys/stat.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include "curl/curl.h"
#include "/src/curl/include/curl/urlapi.h"
#include <cstring>
#include <cstdlib>
#include <iostream>

extern "C" int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    // Initialize CURL globally
    if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
        return 0;
    }

    // Ensure the input data is null-terminated
    std::vector<uint8_t> null_terminated_data(Data, Data + Size);
    null_terminated_data.push_back(0);

    // Create a CURLU handle for curl_url_get
    CURLU *url_handle = curl_url();
    if (url_handle) {
        char *output = nullptr;
        CURLUcode uc = curl_url_set(url_handle, CURLUPART_URL, reinterpret_cast<const char*>(null_terminated_data.data()), 0);
        if (uc == CURLUE_OK) {
            // Try to extract different parts of the URL
            curl_url_get(url_handle, CURLUPART_SCHEME, &output, 0);
            if (output) {
                curl_free(output);
            }
            curl_url_get(url_handle, CURLUPART_HOST, &output, 0);
            if (output) {
                curl_free(output);
            }

            // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from curl_url_get to curl_mime_filedata
            curl_mimepart* ret_curl_mime_addpart_bhpxu = curl_mime_addpart(NULL);
            if (ret_curl_mime_addpart_bhpxu == NULL){
            	return 0;
            }
            // Ensure dataflow is valid (i.e., non-null)
            if (!ret_curl_mime_addpart_bhpxu) {
            	return 0;
            }
            // Ensure dataflow is valid (i.e., non-null)
            if (!output) {
            	return 0;
            }
            CURLcode ret_curl_mime_filedata_udhpz = curl_mime_filedata(ret_curl_mime_addpart_bhpxu, output);
            // End mutation: Producer.APPEND_MUTATOR
            
            curl_url_get(url_handle, CURLUPART_PATH, &output, 0);
            if (output) {
                curl_free(output);
            }
        }
        curl_url_cleanup(url_handle);
    }

    // Create a CURL handle for curl_easy_unescape and curl_easy_escape
    CURL *curl_handle = curl_easy_init();
    if (curl_handle) {
        int outlength;
        char *unescaped = curl_easy_unescape(curl_handle, reinterpret_cast<const char*>(null_terminated_data.data()), Size, &outlength);
        if (unescaped) {
            curl_free(unescaped);
        }

        char *escaped = curl_easy_escape(curl_handle, reinterpret_cast<const char*>(null_terminated_data.data()), Size);
        if (escaped) {
            curl_free(escaped);
        }

        curl_easy_cleanup(curl_handle);
    }

    // Use curl_global_trace
    curl_global_trace(reinterpret_cast<const char*>(null_terminated_data.data()));

    // Use deprecated functions curl_unescape and curl_escape
    char *unescaped_old = curl_unescape(reinterpret_cast<const char*>(null_terminated_data.data()), Size);
    if (unescaped_old) {
        curl_free(unescaped_old);
    }

    char *escaped_old = curl_escape(reinterpret_cast<const char*>(null_terminated_data.data()), Size);
    if (escaped_old) {
        curl_free(escaped_old);
    }

    // Clean up global CURL state
    curl_global_cleanup();

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

    LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
