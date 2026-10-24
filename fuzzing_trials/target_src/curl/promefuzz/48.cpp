// This fuzz driver is generated for library curl, aiming to fuzz the following functions:
// curl_easy_getinfo at easy.c:854:10 in easy.h
// curl_easy_recv at easy.c:1223:10 in easy.h
// curl_easy_duphandle at easy.c:953:7 in easy.h
// curl_easy_cleanup at easy.c:838:6 in easy.h
// curl_easy_reset at easy.c:1084:6 in easy.h
// curl_mime_name at mime.c:1261:10 in curl.h
// curl_easy_perform at easy.c:818:10 in easy.h
// curl_easy_init at easy.c:330:7 in easy.h
// curl_mime_init at mime.c:1202:12 in curl.h
// curl_mime_addpart at mime.c:1236:16 in curl.h
// curl_mime_free at mime.c:1104:6 in curl.h
// curl_easy_cleanup at easy.c:838:6 in easy.h
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

static void fuzz_curl_easy_getinfo(CURL *curl) {
    CURLcode res;
    long response_code = 0;
    res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
}

static void fuzz_curl_easy_recv(CURL *curl) {
    char buffer[1024];
    size_t n;
    CURLcode res = curl_easy_recv(curl, buffer, sizeof(buffer), &n);
}

static void fuzz_curl_easy_duphandle(CURL *curl) {
    CURL *dup_handle = curl_easy_duphandle(curl);
    if (dup_handle) {
        curl_easy_cleanup(dup_handle);
    }
}

static void fuzz_curl_easy_reset(CURL *curl) {
    curl_easy_reset(curl);
}

static void fuzz_curl_mime_name(curl_mimepart *part, const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        // Ensure the string is null-terminated
        std::string name(reinterpret_cast<const char *>(Data), Size);
        curl_mime_name(part, name.c_str());
    }
}

static void fuzz_curl_easy_perform(CURL *curl) {
    CURLcode res = curl_easy_perform(curl);
}

extern "C" int LLVMFuzzerTestOneInput_48(const uint8_t *Data, size_t Size) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        return 0;
    }

    // Fuzz curl_easy_getinfo
    fuzz_curl_easy_getinfo(curl);

    // Fuzz curl_easy_recv
    fuzz_curl_easy_recv(curl);

    // Fuzz curl_easy_duphandle
    fuzz_curl_easy_duphandle(curl);

    // Fuzz curl_easy_reset
    fuzz_curl_easy_reset(curl);

    // Prepare a mime part for curl_mime_name
    curl_mime *mime = curl_mime_init(curl);
    curl_mimepart *part = curl_mime_addpart(mime);
    fuzz_curl_mime_name(part, Data, Size);

    // Fuzz curl_easy_perform
    fuzz_curl_easy_perform(curl);

    // Cleanup
    curl_mime_free(mime);
    curl_easy_cleanup(curl);

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

        LLVMFuzzerTestOneInput_48(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    