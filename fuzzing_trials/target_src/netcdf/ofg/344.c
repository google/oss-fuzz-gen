#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern int nc_delete(const char *);

int LLVMFuzzerTestOneInput_344(const uint8_t *data, size_t size) {
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);

    if (fd == -1) {
        return 0; // Failed to create a temporary file
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(tmpl);
        return 0; // Failed to write data to the file
    }

    close(fd);

    // Call the function-under-test with the temporary filename
    nc_delete(tmpl);

    // Clean up
    unlink(tmpl);

    return 0;
}