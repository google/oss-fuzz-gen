#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <ares.h>

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_164(const uint8_t* data, size_t size);

#ifdef __cplusplus
}
#endif

static ares_socket_t my_socket_callback(ares_socket_t socket_fd, int type, void *data) {
    (void)socket_fd; // Mark as used to avoid unused parameter warning
    (void)type;      // Mark as used to avoid unused parameter warning
    (void)data;      // Mark as used to avoid unused parameter warning
    return ARES_SOCKET_BAD;
}

int LLVMFuzzerTestOneInput_164(const uint8_t* data, size_t size) {
    ares_channel channel;
    struct ares_options options;
    int optmask = 0;

    // Initialize ares library
    if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
        return 0;
    }

    // Initialize the channel
    if (ares_init_options(&channel, &options, optmask) != ARES_SUCCESS) {
        ares_library_cleanup();
        return 0;
    }

    // Set the socket callback
    ares_set_socket_callback(channel, my_socket_callback, (void*)data);

    // Cleanup
    ares_destroy(channel);
    ares_library_cleanup();

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

    LLVMFuzzerTestOneInput_164(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
