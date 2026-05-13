#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Function-under-test
int nc_delete_mp(const char *path, int flag);

// Fuzzing harness
int LLVMFuzzerTestOneInput_288(const uint8_t *data, size_t size) {
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }
    close(fd);

    // Call the function-under-test
    int flag = 0; // Example flag, can be varied for testing

    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of nc_delete_mp
    nc_delete_mp(tmpl, 64);
    // End mutation: Producer.REPLACE_ARG_MUTATOR



    // Clean up
    unlink(tmpl);

    return 0;
}