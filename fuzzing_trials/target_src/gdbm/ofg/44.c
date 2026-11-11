#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_44(const uint8_t *data, size_t size) {
    // Create a temporary file to use as the database
    char tmpl[] = "/tmp/gdbmfuzzXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        perror("mkstemp");
        return 0;
    }

    // Open the GDBM database
    GDBM_FILE dbf = gdbm_open(tmpl, 512, GDBM_NEWDB, 0666, NULL);
    if (!dbf) {
        perror("gdbm_open");
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Write the fuzz data to the database
    datum key, value;
    key.dptr = (char *)"fuzzkey";
    key.dsize = 7;
    value.dptr = (char *)data;
    value.dsize = size;
    if (gdbm_store(dbf, key, value, GDBM_REPLACE) != 0) {
        perror("gdbm_store");
        gdbm_close(dbf);
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Call the function under test
    int dump_format = 0; // Use a specific dump format
    int dump_flags = 0;  // Use specific dump flags
    int result = gdbm_dump(dbf, tmpl, dump_format, dump_flags, 0);

    // Clean up
    gdbm_close(dbf);
    close(fd);
    unlink(tmpl);

    return result;
}