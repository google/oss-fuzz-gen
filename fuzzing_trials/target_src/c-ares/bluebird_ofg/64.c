#include <string.h>
#include <sys/stat.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "ares.h"

// Define a dummy socket callback function
static ares_socket_t dummy_socket_callback(ares_channel channel, ares_socket_t socket_fd, int type, void *data) {
    (void)channel; // Mark channel as unused
    (void)type; // Mark type as unused
    (void)data; // Mark data as unused
    // Simply return the socket_fd without any modification
    return socket_fd;
}

int LLVMFuzzerTestOneInput_64(const uint8_t *data, size_t size) {
    ares_channel channel;
    struct ares_options options;
    int optmask = 0;

    // Initialize the c-ares library and create a channel
    if (ares_init_options(&channel, &options, optmask) != ARES_SUCCESS) {
        return 0;
    }

    // Use some of the input data as a pointer to pass to the callback
    void *callback_data = (void *)data;

    // Call the function-under-test
    ares_set_socket_callback(channel, dummy_socket_callback, callback_data);

    // Clean up the c-ares channel
    ares_destroy(channel);

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

    LLVMFuzzerTestOneInput_64(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
