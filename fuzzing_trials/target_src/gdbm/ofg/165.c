#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_165(const uint8_t *data, size_t size) {
    // Create a temporary file to act as the database file
    char tmpl[] = "/tmp/fuzzdbXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        perror("mkstemp");
        return 0;
    }
    close(fd);

    // Ensure the data is written to the file
    FILE *file = fopen(tmpl, "wb");
    if (!file) {
        perror("fopen");
        return 0;
    }
    fwrite(data, 1, size, file);
    fclose(file);

    // Open the GDBM database file
    GDBM_FILE dbf = gdbm_open(tmpl, 512, GDBM_WRCREAT, 0666, NULL);

    // Clean up
    if (dbf) {
        gdbm_close(dbf);
    }
    unlink(tmpl); // Remove the temporary file

    return 0;
}