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
#include "/src/curl/include/curl/websockets.h"

static void setup_curl(CURL *curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "ws://example.com");
    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);
}

static void perform_connection(CURL *curl) {
    CURLcode res = curl_easy_perform(curl);
    if(res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    }
}

extern "C" int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size) {
    CURL *curl = curl_easy_init();
    if(!curl) {
        return 0;
    }

    setup_curl(curl);
    perform_connection(curl);

    // Allocate buffers
    void *buffer = malloc(Size);
    if(!buffer) {
        curl_easy_cleanup(curl);
        return 0;
    }
    memcpy(buffer, Data, Size);

    size_t sent = 0, recv = 0;
    const struct curl_ws_frame *meta = nullptr;
    
    // Fuzz curl_ws_send
    curl_ws_send(curl, buffer, Size, &sent, 0, 0);

    // Fuzz curl_easy_send
    curl_easy_send(curl, buffer, Size, &sent);

    // Fuzz curl_easy_recv
    curl_easy_recv(curl, buffer, Size, &recv);

    // Fuzz curl_ws_recv
    curl_ws_recv(curl, buffer, Size, &recv, &meta);

    // Fuzz curl_ws_start_frame
    curl_ws_start_frame(curl, 0, Size);

    // Fuzz curl_ws_meta
    curl_ws_meta(curl);

    // Cleanup
    free(buffer);
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

    LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
