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
#include "/src/curl/include/curl/easy.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>

extern "C" int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    // Fuzz curl_easy_duphandle
    CURL *dup_handle = curl_easy_duphandle(curl);
    if (dup_handle) {
        curl_easy_cleanup(dup_handle);
    }

    // Fuzz curl_easy_perform
    CURLcode res = curl_easy_perform(curl);

    // Fuzz curl_easy_send and curl_easy_recv if connection is established
    if (res == CURLE_OK) {
        char buffer[256];
        size_t n;

        // Fuzz curl_easy_send
        curl_easy_send(curl, Data, Size, &n);

        // Fuzz curl_easy_recv
        curl_easy_recv(curl, buffer, sizeof(buffer), &n);
    }

    // Fuzz curl_share_setopt
    CURLSH *share = curl_share_init();
    if (share) {
        CURLSHcode sh_res = curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);
        curl_share_cleanup(share);
    }

    // Fuzz curl_easy_ssls_import
    const char *session_key = "dummy_key";
    const unsigned char *shmac = Data;
    size_t shmac_len = (Size > 20) ? 20 : Size;
    const unsigned char *sdata = Data;
    size_t sdata_len = Size;

    curl_easy_ssls_import(curl, session_key, shmac, shmac_len, sdata, sdata_len);

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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
