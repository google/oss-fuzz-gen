#include <gdbm.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput_160(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0; // Not enough data to proceed
    }

    // Create a temporary file name for the GDBM database
    char filename[] = "/tmp/gdbm_fuzzXXXXXX";
    int fd = mkstemp(filename);
    if (fd == -1) {
        return 0; // Failed to create a temporary file
    }
    close(fd);

    // Open a GDBM database using the temporary file
    GDBM_FILE db = gdbm_open(filename, 0, GDBM_NEWDB, 0644, NULL);
    if (!db) {
        unlink(filename); // Clean up the temporary file
        return 0; // Failed to open database
    }

    // Prepare key and value datum structures
    datum key, value;
    key.dptr = (char *)data;
    key.dsize = size / 2;

    value.dptr = (char *)(data + size / 2);
    value.dsize = size - key.dsize;

    // Use a constant flag value for the store operation
    int flag = GDBM_INSERT;

    // Call the function-under-test
    gdbm_store(db, key, value, flag);

    // Close the database
    gdbm_close(db);

    // Clean up the temporary file
    unlink(filename);

    return 0;
}