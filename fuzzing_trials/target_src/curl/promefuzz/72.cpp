// This fuzz driver is generated for library curl, aiming to fuzz the following functions:
// curl_multi_init at multi.c:356:8 in multi.h
// curl_multi_poll at multi.c:1665:11 in multi.h
// curl_multi_perform at multi.c:2857:11 in multi.h
// curl_multi_timeout at multi.c:3465:11 in multi.h
// curl_multi_socket_action at multi.c:3362:11 in multi.h
// curl_multi_setopt at multi.c:3224:11 in multi.h
// curl_multi_socket_all at multi.c:3373:11 in multi.h
// curl_multi_cleanup at multi.c:2867:11 in multi.h
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
#include <cstring>
#include <fstream>

extern "C" int LLVMFuzzerTestOneInput_72(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(curl_socket_t) + sizeof(int)) {
        return 0;
    }

    // Initialize CURLM handle
    CURLM *multi_handle = curl_multi_init();
    if (!multi_handle) {
        return 0;
    }

    // Prepare data for curl_multi_poll
    struct curl_waitfd extra_fds[1];
    memset(extra_fds, 0, sizeof(extra_fds));
    unsigned int extra_nfds = 1;
    int timeout_ms = 1000;
    int poll_ret = 0;

    // Call curl_multi_poll
    curl_multi_poll(multi_handle, extra_fds, extra_nfds, timeout_ms, &poll_ret);

    // Prepare data for curl_multi_perform
    int running_handles = 0;

    // Call curl_multi_perform
    curl_multi_perform(multi_handle, &running_handles);

    // Prepare data for curl_multi_timeout
    long timeout = 0;

    // Call curl_multi_timeout
    curl_multi_timeout(multi_handle, &timeout);

    // Prepare data for curl_multi_socket
    curl_socket_t socket = *reinterpret_cast<const curl_socket_t*>(Data);
    int running_handles_socket = 0;

    // Call curl_multi_socket
    curl_multi_socket(multi_handle, socket, &running_handles_socket);

    // Prepare data for curl_multi_setopt
    CURLMoption option = CURLMOPT_PIPELINING;
    curl_multi_setopt(multi_handle, option, 1L);

    // Prepare data for curl_multi_socket_all
    int running_handles_all = 0;

    // Call curl_multi_socket_all
    curl_multi_socket_all(multi_handle, &running_handles_all);

    // Clean up
    curl_multi_cleanup(multi_handle);

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

        LLVMFuzzerTestOneInput_72(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    