// This fuzz driver is generated for library curl, aiming to fuzz the following functions:
// curl_global_init at easy.c:197:10 in curl.h
// curl_url at urlapi.c:1281:8 in urlapi.h
// curl_url_set at urlapi.c:1801:11 in urlapi.h
// curl_url_get at urlapi.c:1536:11 in urlapi.h
// curl_free at escape.c:190:6 in curl.h
// curl_url_get at urlapi.c:1536:11 in urlapi.h
// curl_free at escape.c:190:6 in curl.h
// curl_url_get at urlapi.c:1536:11 in urlapi.h
// curl_free at escape.c:190:6 in curl.h
// curl_url_cleanup at urlapi.c:1286:6 in urlapi.h
// curl_easy_init at easy.c:330:7 in easy.h
// curl_easy_unescape at escape.c:163:7 in curl.h
// curl_free at escape.c:190:6 in curl.h
// curl_easy_escape at escape.c:50:7 in curl.h
// curl_free at escape.c:190:6 in curl.h
// curl_easy_cleanup at easy.c:838:6 in easy.h
// curl_global_trace at easy.c:292:10 in curl.h
// curl_unescape at escape.c:42:7 in curl.h
// curl_free at escape.c:190:6 in curl.h
// curl_escape at escape.c:36:7 in curl.h
// curl_free at escape.c:190:6 in curl.h
// curl_global_cleanup at easy.c:255:6 in curl.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <curl/curl.h>
#include <curl/urlapi.h>
#include <cstring>
#include <cstdlib>
#include <iostream>

extern "C" int LLVMFuzzerTestOneInput_70(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

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

        LLVMFuzzerTestOneInput_70(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    