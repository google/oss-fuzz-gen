// This fuzz driver is generated for library curl, aiming to fuzz the following functions:
// curl_multi_init at multi.c:356:8 in multi.h
// curl_easy_init at easy.c:330:7 in easy.h
// curl_multi_cleanup at multi.c:2867:11 in multi.h
// curl_easy_cleanup at easy.c:838:6 in easy.h
// curl_multi_add_handle at multi.c:454:11 in multi.h
// curl_easy_cleanup at easy.c:838:6 in easy.h
// curl_multi_cleanup at multi.c:2867:11 in multi.h
// curl_multi_remove_handle at multi.c:776:11 in multi.h
// curl_multi_socket_action at multi.c:3362:11 in multi.h
// curl_multi_wakeup at multi.c:1674:11 in multi.h
// curl_multi_fdset at multi.c:1247:11 in multi.h
// curl_multi_strerror at strerror.c:326:13 in multi.h
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
#include <iostream>
#include <cstring>
#include <sys/select.h>
#include <unistd.h>

extern "C" int LLVMFuzzerTestOneInput_60(const uint8_t *Data, size_t Size) {
    // Initialize CURLM and CURL handles
    CURLM *multi_handle = curl_multi_init();
    CURL *easy_handle = curl_easy_init();

    if (!multi_handle || !easy_handle) {
        // Cleanup and return if initialization failed
        if (multi_handle) curl_multi_cleanup(multi_handle);
        if (easy_handle) curl_easy_cleanup(easy_handle);
        return 0;
    }

    // Add the easy handle to the multi stack
    CURLMcode result = curl_multi_add_handle(multi_handle, easy_handle);
    if (result != CURLM_OK) {
        // Cleanup and return if adding handle failed
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Randomly decide whether to remove the handle
    if (Size > 0 && Data[0] % 2 == 0) {
        result = curl_multi_remove_handle(multi_handle, easy_handle);
    }

    // Perform socket action if enough data is available
    if (Size > 2) { // Ensure we have enough data to access Data[2]
        int running_handles;
        curl_socket_t socket = static_cast<curl_socket_t>(Data[1]);
        int ev_bitmask = static_cast<int>(Data[2] % 4); // Simulate some event bitmask
        result = curl_multi_socket_action(multi_handle, socket, ev_bitmask, &running_handles);
    }

    // Wake up the multi handle
    result = curl_multi_wakeup(multi_handle);

    // Use fdset if more data is available
    if (Size > 3) {
        fd_set read_fd_set, write_fd_set, exc_fd_set;
        FD_ZERO(&read_fd_set);
        FD_ZERO(&write_fd_set);
        FD_ZERO(&exc_fd_set);
        int max_fd;

        result = curl_multi_fdset(multi_handle, &read_fd_set, &write_fd_set, &exc_fd_set, &max_fd);
        if (result == CURLM_OK && max_fd >= 0) {
            struct timeval timeout;
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;
            select(max_fd + 1, &read_fd_set, &write_fd_set, &exc_fd_set, &timeout);
        }
    }

    // Convert the result to a human-readable string
    const char *error_str = curl_multi_strerror(result);
    if (error_str) {
        std::cout << "CURLMcode: " << error_str << std::endl;
    }

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

        LLVMFuzzerTestOneInput_60(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    