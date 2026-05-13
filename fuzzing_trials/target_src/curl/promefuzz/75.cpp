// This fuzz driver is generated for library curl, aiming to fuzz the following functions:
// curl_multi_init at multi.c:356:8 in multi.h
// curl_multi_poll at multi.c:1665:11 in multi.h
// curl_formget at formdata.c:626:5 in curl.h
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
#include <curl/curl.h>
#include <curl/typecheck-gcc.h>
#include <curl/multi.h>
#include <cstdint>
#include <cstdio>

static size_t formget_callback(void *arg, const char *buf, size_t len) {
    return len;
}

extern "C" int LLVMFuzzerTestOneInput_75(const uint8_t *Data, size_t Size) {
    CURLM *multi_handle = curl_multi_init();
    if (!multi_handle) {
        return 0;
    }

    struct curl_waitfd extra_fds[1];
    extra_fds[0].fd = 0;
    extra_fds[0].events = CURL_WAIT_POLLIN;
    extra_fds[0].revents = 0;

    int timeout_ms = 1000;
    int ret;
    
    curl_multi_poll(multi_handle, extra_fds, 1, timeout_ms, &ret);

    struct curl_httppost *formpost = nullptr;
    curl_formget(formpost, nullptr, formget_callback);

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

        LLVMFuzzerTestOneInput_75(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    