#include "/src/gdbm/src/gdbm.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_96(const uint8_t *data, size_t size) {
    if (size < 1) return 0; // Ensure there is data to process

    // Create a temporary file
    char tmpl[] = "/tmp/fuzzdbXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        perror("mkstemp");
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != size) {
        perror("write");
        close(fd);
        unlink(tmpl);
        return 0;
    }
    close(fd);

    // Open the GDBM file
    GDBM_FILE dbf = gdbm_open(tmpl, 512, GDBM_WRCREAT, 0666, NULL);
    if (!dbf) {
        unlink(tmpl);
        return 0;
    }

    // Initialize a datum structure
    datum key;
    key.dptr = (char *)data;
    key.dsize = size;

    // Call the function-under-test
    datum next_key = gdbm_nextkey(dbf, key);

    // Free the memory allocated by gdbm_nextkey
    if (next_key.dptr) {
        free(next_key.dptr);
    }

    // Close the GDBM file and remove the temporary file
    gdbm_close(dbf);
    unlink(tmpl);

    return 0;
}