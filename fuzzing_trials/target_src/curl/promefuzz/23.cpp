// This fuzz driver is generated for library curl, aiming to fuzz the following functions:
// curl_multi_init at multi.c:356:8 in multi.h
// curl_easy_init at easy.c:330:7 in easy.h
// curl_multi_cleanup at multi.c:2867:11 in multi.h
// curl_easy_cleanup at easy.c:838:6 in easy.h
// curl_multi_notify_enable at multi.c:4053:11 in multi.h
// curl_multi_perform at multi.c:2857:11 in multi.h
// curl_multi_wakeup at multi.c:1674:11 in multi.h
// curl_multi_add_handle at multi.c:454:11 in multi.h
// curl_multi_setopt at multi.c:3224:11 in multi.h
// curl_multi_socket_all at multi.c:3373:11 in multi.h
// curl_multi_remove_handle at multi.c:776:11 in multi.h
// curl_easy_cleanup at easy.c:838:6 in easy.h
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
#include <cstdint>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    CURLM *multi_handle = curl_multi_init();
    CURL *easy_handle = curl_easy_init();

    if (!multi_handle || !easy_handle) {
        if (multi_handle) curl_multi_cleanup(multi_handle);
        if (easy_handle) curl_easy_cleanup(easy_handle);
        return 0;
    }

    int running_handles = 0;
    unsigned int notification = Data[0];
    CURLMcode res;

    // Fuzz curl_multi_notify_enable
    res = curl_multi_notify_enable(multi_handle, notification);

    // Fuzz curl_multi_perform
    res = curl_multi_perform(multi_handle, &running_handles);

    // Fuzz curl_multi_wakeup
    res = curl_multi_wakeup(multi_handle);

    // Fuzz curl_multi_add_handle
    res = curl_multi_add_handle(multi_handle, easy_handle);

    // Fuzz curl_multi_setopt
    if (Size > 1) {
        CURLMoption option = static_cast<CURLMoption>(Data[1]);
        res = curl_multi_setopt(multi_handle, option, nullptr);
    }

    // Fuzz curl_multi_socket_all
    res = curl_multi_socket_all(multi_handle, &running_handles);

    // Cleanup
    curl_multi_remove_handle(multi_handle, easy_handle);
    curl_easy_cleanup(easy_handle);
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

        LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    