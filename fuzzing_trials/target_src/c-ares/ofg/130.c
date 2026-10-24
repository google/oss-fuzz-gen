#include <stddef.h>
#include <sys/select.h>
#include <ares.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput_130(const uint8_t *data, size_t size) {
    // Initialize the ares library
    ares_library_init(ARES_LIB_INIT_ALL);

    // Create an ares channel
    ares_channel channel;
    int status = ares_init(&channel);
    if (status != ARES_SUCCESS) {
        return 0;
    }

    // Initialize file descriptor sets
    fd_set read_fds;
    fd_set write_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);

    // Call the function-under-test
    ares_fds(channel, &read_fds, &write_fds);

    // Clean up
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

    LLVMFuzzerTestOneInput_130(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
