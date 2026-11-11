#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

// Function-under-test
int nc_create(const char *path, int flags, int *fd);

int LLVMFuzzerTestOneInput_396(const uint8_t *data, size_t size) {
    if (size < 4) {
        return 0; // Not enough data to proceed
    }

    // Create a temporary file name
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // Failed to create a temporary file
    }

    // Write the fuzz data to the temporary file
    write(fd, data, size);
    close(fd);

    // Prepare arguments for nc_create
    int flags = O_RDWR; // Example flag, can be varied
    int result_fd;

    // Call the function-under-test
    nc_create(tmpl, flags, &result_fd);

    // Clean up the temporary file
    unlink(tmpl);

    return 0;
}