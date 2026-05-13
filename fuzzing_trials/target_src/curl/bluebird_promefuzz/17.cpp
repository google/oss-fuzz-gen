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
#include "/src/curl/include/curl/multi.h"
#include <cstdint>
#include <cstdlib>
#include <cstdio>

static CURLM *create_multi_handle() {
    return curl_multi_init();
}

static CURL *create_easy_handle() {
    return curl_easy_init();
}

extern "C" int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(curl_socket_t) + sizeof(long)) {
        return 0; // Not enough data to proceed
    }

    CURLM *multi_handle = create_multi_handle();
    if (!multi_handle) {
        return 0;
    }
    
    CURL *easy_handle = create_easy_handle();
    if (!easy_handle) {
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    curl_socket_t sockfd = *(reinterpret_cast<const curl_socket_t*>(Data));
    long timeout_ms = *(reinterpret_cast<const long*>(Data + sizeof(curl_socket_t)));

    // Fuzz curl_multi_add_handle
    curl_multi_add_handle(multi_handle, easy_handle);

    // Fuzz curl_multi_assign
    curl_multi_assign(multi_handle, sockfd, nullptr);

    // Fuzz curl_multi_wait
    struct curl_waitfd extra_fds[1];
    int ret;
    curl_multi_wait(multi_handle, extra_fds, 1, timeout_ms, &ret);

    // Fuzz curl_multi_timeout
    long timeout;
    curl_multi_timeout(multi_handle, &timeout);

    // Fuzz curl_multi_remove_handle
    curl_multi_remove_handle(multi_handle, easy_handle);

    // Cleanup
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

    LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
