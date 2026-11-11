// This fuzz driver is generated for library curl, aiming to fuzz the following functions:
// curl_easy_getinfo at easy.c:854:10 in easy.h
// curl_escape at escape.c:36:7 in curl.h
// curl_free at escape.c:190:6 in curl.h
// curl_easy_init at easy.c:330:7 in easy.h
// curl_easy_setopt at setopt.c:2903:10 in easy.h
// curl_easy_cleanup at easy.c:838:6 in easy.h
// curl_easy_init at easy.c:330:7 in easy.h
// curl_url at urlapi.c:1281:8 in urlapi.h
// curl_easy_setopt at setopt.c:2903:10 in easy.h
// curl_url_cleanup at urlapi.c:1286:6 in urlapi.h
// curl_easy_cleanup at easy.c:838:6 in easy.h
// curl_easy_init at easy.c:330:7 in easy.h
// curl_easy_setopt at setopt.c:2903:10 in easy.h
// curl_easy_cleanup at easy.c:838:6 in easy.h
// curl_easy_getinfo at easy.c:854:10 in easy.h
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

extern "C" int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Fuzzing Wcurl_easy_getinfo_err_long
    long info_value = 0;
    CURLcode res = curl_easy_getinfo(NULL, static_cast<CURLINFO>(Data[0]), &info_value);

    // Fuzzing curl_escape
    char *escaped = curl_escape(reinterpret_cast<const char *>(Data), Size);
    if (escaped) {
        curl_free(escaped);
    }

    // Fuzzing Wcurl_easy_setopt_err_sockopt_cb
    CURL *curl = curl_easy_init();
    if (curl) {
        res = curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, reinterpret_cast<curl_sockopt_callback>(const_cast<uint8_t *>(Data)));
        curl_easy_cleanup(curl);
    }

    // Fuzzing Wcurl_easy_setopt_err_curlu
    curl = curl_easy_init();
    if (curl) {
        CURLU *url = curl_url();
        if (url) {
            res = curl_easy_setopt(curl, CURLOPT_CURLU, url);
            curl_url_cleanup(url);
        }
        curl_easy_cleanup(curl);
    }

    // Fuzzing Wcurl_easy_setopt_err_trailer_cb
    curl = curl_easy_init();
    if (curl) {
        res = curl_easy_setopt(curl, CURLOPT_TRAILERFUNCTION, reinterpret_cast<curl_trailer_callback>(const_cast<uint8_t *>(Data)));
        curl_easy_cleanup(curl);
    }

    // Fuzzing Wcurl_easy_getinfo_err_curl_off_t
    curl_off_t off_value = 0;
    res = curl_easy_getinfo(NULL, static_cast<CURLINFO>(Data[0]), &off_value);

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

        LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    