// This fuzz driver is generated for library curl, aiming to fuzz the following functions:
// curl_easy_init at easy.c:330:7 in easy.h
// curl_easy_cleanup at easy.c:838:6 in easy.h
// curl_easy_setopt at setopt.c:2903:10 in easy.h
// curl_easy_setopt at setopt.c:2903:10 in easy.h
// curl_easy_perform at easy.c:818:10 in easy.h
// curl_easy_cleanup at easy.c:838:6 in easy.h
// curl_ws_send at ws.c:1768:10 in websockets.h
// curl_easy_send at easy.c:1301:10 in easy.h
// curl_easy_recv at easy.c:1223:10 in easy.h
// curl_ws_recv at ws.c:1530:10 in websockets.h
// curl_ws_start_frame at ws.c:1871:22 in websockets.h
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
#include <curl/websockets.h>

extern "C" int LLVMFuzzerTestOneInput_20(const uint8_t *Data, size_t Size) {
    // Initialize CURL
    CURL *curl = curl_easy_init();
    if (!curl) {
        return 0;
    }

    // Prepare a dummy file for any file operations
    FILE *dummy_file = fopen("./dummy_file", "wb");
    if (!dummy_file) {
        curl_easy_cleanup(curl);
        return 0;
    }
    fwrite(Data, 1, Size, dummy_file);
    fclose(dummy_file);

    // Set CURL options for CONNECT_ONLY
    curl_easy_setopt(curl, CURLOPT_URL, "ws://localhost:8080");
    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);

    // Perform the connection
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        return 0;
    }

    // Prepare buffers and variables for sending/receiving
    size_t sent = 0;
    size_t received = 0;
    unsigned int flags = 0;
    curl_off_t fragsize = 0;
    const struct curl_ws_frame *metap = nullptr;

    // Test curl_ws_send
    res = curl_ws_send(curl, Data, Size, &sent, fragsize, flags);

    // Test curl_easy_send
    res = curl_easy_send(curl, Data, Size, &sent);

    // Prepare a buffer for receiving data
    char recv_buffer[1024];
    size_t recv_size = sizeof(recv_buffer);

    // Test curl_easy_recv
    res = curl_easy_recv(curl, recv_buffer, recv_size, &received);

    // Test curl_ws_recv
    res = curl_ws_recv(curl, recv_buffer, recv_size, &received, &metap);

    // Test curl_ws_start_frame
    res = curl_ws_start_frame(curl, flags, fragsize);

    // Cleanup
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

        LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    