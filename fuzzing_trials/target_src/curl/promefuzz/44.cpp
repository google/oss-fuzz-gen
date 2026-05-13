// This fuzz driver is generated for library curl, aiming to fuzz the following functions:
// curl_multi_init at multi.c:356:8 in multi.h
// curl_multi_cleanup at multi.c:2867:11 in multi.h
// curl_multi_poll at multi.c:1665:11 in multi.h
// curl_multi_perform at multi.c:2857:11 in multi.h
// curl_multi_timeout at multi.c:3465:11 in multi.h
// curl_multi_socket_action at multi.c:3362:11 in multi.h
// curl_multi_setopt at multi.c:3224:11 in multi.h
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
#include <cstdlib>
#include <cstdio>

static CURLM *initMultiHandle() {
    CURLM *multi_handle = curl_multi_init();
    return multi_handle;
}

static void cleanupMultiHandle(CURLM *multi_handle) {
    if (multi_handle) {
        curl_multi_cleanup(multi_handle);
    }
}

extern "C" int LLVMFuzzerTestOneInput_44(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) {
        return 0;
    }

    CURLM *multi_handle = initMultiHandle();
    if (!multi_handle) {
        return 0;
    }

    int running_handles = 0;
    long timeout_ms = 0;
    struct curl_waitfd extra_fds[1] = {0};
    unsigned int extra_nfds = 1;
    int ret = 0;

    // Fuzz curl_multi_poll
    curl_multi_poll(multi_handle, extra_fds, extra_nfds, *reinterpret_cast<const int*>(Data), &ret);

    // Fuzz curl_multi_perform
    curl_multi_perform(multi_handle, &running_handles);

    // Fuzz curl_multi_timeout
    curl_multi_timeout(multi_handle, &timeout_ms);

    // Fuzz curl_multi_socket
    curl_socket_t s = 0;
    curl_multi_socket(multi_handle, s, &running_handles);

    // Fuzz curl_multi_setopt
    CURLMoption option = CURLMOPT_PIPELINING;
    curl_multi_setopt(multi_handle, option, 1L);

    // Fuzz curl_multi_socket_all
    curl_multi_socket_all(multi_handle, &running_handles);

    cleanupMultiHandle(multi_handle);
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

        LLVMFuzzerTestOneInput_44(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    