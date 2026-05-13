#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_107(const uint8_t *data, size_t size) {
    if (size < 1) return 0; // Ensure there's at least some data

    // Create a temporary file to act as the GDBM database
    char tmpl[] = "/tmp/gdbm_fuzzXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        perror("mkstemp");
        return 0;
    }
    close(fd);

    // Open the GDBM database
    GDBM_FILE dbf = gdbm_open(tmpl, 512, GDBM_NEWDB, 0666, NULL);
    if (!dbf) {
        perror("gdbm_open");
        unlink(tmpl);
        return 0;
    }

    // Prepare a datum key from the input data
    datum key;
    key.dptr = (char *)data;
    key.dsize = size;

    // Call the function-under-test
    datum result = gdbm_fetch(dbf, key);

    // Clean up
    if (result.dptr) {
        free(result.dptr);
    }
    gdbm_close(dbf);
    unlink(tmpl);

    return 0;
}