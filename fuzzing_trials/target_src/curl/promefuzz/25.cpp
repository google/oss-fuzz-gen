// This fuzz driver is generated for library curl, aiming to fuzz the following functions:
// curl_multi_init at multi.c:356:8 in multi.h
// curl_multi_cleanup at multi.c:2867:11 in multi.h
// curl_multi_assign at multi.c:3724:11 in multi.h
// curl_multi_poll at multi.c:1665:11 in multi.h
// curl_multi_wait at multi.c:1656:11 in multi.h
// curl_multi_perform at multi.c:2857:11 in multi.h
// curl_multi_info_read at multi.c:2973:10 in multi.h
// curl_multi_socket_all at multi.c:3373:11 in multi.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <curl/multi.h>
#include <cstdint>
#include <cstring>
#include <cstdio>

static CURLM *initialize_multi_handle() {
    CURLM *multi_handle = curl_multi_init();
    if (!multi_handle) {
        fprintf(stderr, "Failed to initialize CURLM handle\n");
    }
    return multi_handle;
}

static void cleanup_multi_handle(CURLM *multi_handle) {
    if (multi_handle) {
        curl_multi_cleanup(multi_handle);
    }
}

extern "C" int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(curl_socket_t)) {
        return 0;
    }

    CURLM *multi_handle = initialize_multi_handle();
    if (!multi_handle) {
        return 0;
    }

    curl_socket_t sockfd = *reinterpret_cast<const curl_socket_t*>(Data);
    void *sockp = nullptr;
    CURLMcode res;

    // Test curl_multi_assign
    res = curl_multi_assign(multi_handle, sockfd, sockp);
    if (res != CURLM_OK) {
        fprintf(stderr, "curl_multi_assign failed: %d\n", res);
    }

    // Test curl_multi_poll
    struct curl_waitfd extra_fds[1];
    memset(extra_fds, 0, sizeof(extra_fds));
    int ret;
    res = curl_multi_poll(multi_handle, extra_fds, 1, 1000, &ret);
    if (res != CURLM_OK) {
        fprintf(stderr, "curl_multi_poll failed: %d\n", res);
    }

    // Test curl_multi_wait
    res = curl_multi_wait(multi_handle, extra_fds, 1, 1000, &ret);
    if (res != CURLM_OK) {
        fprintf(stderr, "curl_multi_wait failed: %d\n", res);
    }

    // Test curl_multi_perform
    int running_handles;
    res = curl_multi_perform(multi_handle, &running_handles);
    if (res != CURLM_OK) {
        fprintf(stderr, "curl_multi_perform failed: %d\n", res);
    }

    // Test curl_multi_info_read
    int msgs_in_queue;
    CURLMsg *msg = curl_multi_info_read(multi_handle, &msgs_in_queue);
    if (msg) {
        fprintf(stderr, "Message received: %d\n", msg->msg);
    }

    // Test curl_multi_socket_all
    res = curl_multi_socket_all(multi_handle, &running_handles);
    if (res != CURLM_OK) {
        fprintf(stderr, "curl_multi_socket_all failed: %d\n", res);
    }

    cleanup_multi_handle(multi_handle);
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

        LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    