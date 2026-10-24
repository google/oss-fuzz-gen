#include <ares.h>
#include <sys/select.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_16(const uint8_t* data, size_t size) {
    // Initialize ares library
    static int initialized = 0;
    if (!initialized) {
        ares_library_init(ARES_LIB_INIT_ALL);
        initialized = 1;
    }

    // Create a channel
    ares_channel channel;
    int status = ares_init(&channel);
    if (status != ARES_SUCCESS) {
        return 0;
    }

    // Prepare file descriptor sets
    fd_set read_fds;
    fd_set write_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);

    // Simulate the behavior of FuzzedDataProvider
    int max_fd = (size > 0) ? data[0] % FD_SETSIZE : 0;
    for (int i = 0; i < max_fd; ++i) {
        if (size > 1 && data[i % size] % 2) {
            FD_SET(i, &read_fds);
        }
        if (size > 2 && data[(i + 1) % size] % 2) {
            FD_SET(i, &write_fds);
        }
    }

    // Call the function under test
    ares_process(channel, &read_fds, &write_fds);

    // Clean up
    ares_destroy(channel);

    return 0;
}