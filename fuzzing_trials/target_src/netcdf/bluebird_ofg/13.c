#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Function-under-test
int nc_delete(const char *filename);

int LLVMFuzzerTestOneInput_13(const uint8_t *data, size_t size) {
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);

    if (fd == -1) {
        return 0; // If creating the temp file fails, exit early
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    close(fd);

    // Call the function-under-test with the temporary filename
    nc_delete(tmpl);

    // Clean up the temporary file
    unlink(tmpl);

    return 0;
}