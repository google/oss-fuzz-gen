#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function-under-test declaration
int nc_create(const char *path, int flags, int *output);

// Fuzzing harness
int LLVMFuzzerTestOneInput_397(const uint8_t *data, size_t size) {
    // Ensure the data size is large enough to extract meaningful inputs
    if (size < 5) return 0;

    // Create a temporary file to use as a path input
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        perror("mkstemp");
        return 0;
    }
    close(fd);

    // Use the first byte of data as an integer flag
    int flags = (int)data[0];

    // Use the next four bytes as an integer output
    int output;
    memcpy(&output, data + 1, sizeof(int));

    // Call the function-under-test
    nc_create(tmpl, flags, &output);

    // Clean up the temporary file
    remove(tmpl);

    return 0;
}