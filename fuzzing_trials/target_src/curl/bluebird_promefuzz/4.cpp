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
#include "/src/curl/include/curl/multi.h"
#include <cstdint>
#include <cstring>
#include <cstdio>

static void fuzz_curl_share_setopt(CURLSH *share) {
    CURLSHcode res;
    CURLSHoption options[] = {CURLSHOPT_SHARE, CURLSHOPT_UNSHARE};
    for (CURLSHoption option : options) {
        res = curl_share_setopt(share, option, CURL_LOCK_DATA_COOKIE);
        if (res != CURLSHE_OK) {
            const char *error = curl_share_strerror(res);
            if (error) {
                fprintf(stderr, "curl_share_setopt error: %s\n", error);
            }
        }
    }
}

static void fuzz_curl_share_cleanup(CURLSH *share) {
    CURLSHcode res = curl_share_cleanup(share);
    if (res != CURLSHE_OK) {
        const char *error = curl_share_strerror(res);
        if (error) {
            fprintf(stderr, "curl_share_cleanup error: %s\n", error);
        }
    }
}

static void fuzz_curl_getdate(const char *date_str) {
    time_t date = curl_getdate(date_str, NULL);
    if (date == -1) {
        fprintf(stderr, "Failed to parse date: %s\n", date_str);
    } else {
        printf("Parsed date: %ld\n", (long)date);
    }
}

extern "C" int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    CURLSH *share = curl_share_init();
    if (!share) return 0;

    // Fuzz curl_share_setopt
    fuzz_curl_share_setopt(share);

    // Fuzz curl_getdate
    char date_str[256];
    size_t copy_size = Size < 255 ? Size : 255;
    memcpy(date_str, Data, copy_size);
    date_str[copy_size] = '\0';
    fuzz_curl_getdate(date_str);

    // Fuzz curl_share_cleanup
    fuzz_curl_share_cleanup(share);

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
