#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_72(const uint8_t *data, size_t size) {
    if (size < sizeof(int) + sizeof(int)) {
        return 0;
    }

    // Create a temporary file to use as the GDBM database
    char tmpl[] = "/tmp/fuzzdbXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        perror("mkstemp");
        return 0;
    }

    // Close the file descriptor as gdbm_open will open it
    close(fd);

    // Open the GDBM database
    GDBM_FILE dbf = gdbm_open(tmpl, 512, GDBM_NEWDB, 0666, NULL);
    if (!dbf) {
        unlink(tmpl);
        return 0;
    }

    // Extract option and option size from the input data
    int option = *((int *)data);
    int option_size = *((int *)(data + sizeof(int)));

    // Ensure the option value is not NULL and has a valid size
    if (size < sizeof(int) + sizeof(int) + option_size) {
        gdbm_close(dbf);
        unlink(tmpl);
        return 0;
    }

    // Allocate memory for the option value
    void *option_value = malloc(option_size);
    if (!option_value) {
        gdbm_close(dbf);
        unlink(tmpl);
        return 0;
    }

    // Copy the option value from the input data
    memcpy(option_value, data + sizeof(int) + sizeof(int), option_size);

    // Call the function-under-test
    gdbm_setopt(dbf, option, option_value, option_size);

    // Clean up
    free(option_value);
    gdbm_close(dbf);
    unlink(tmpl);

    return 0;
}