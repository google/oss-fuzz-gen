#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

int LLVMFuzzerTestOneInput_108(const uint8_t *data, size_t size) {
    // Create a temporary file to act as a GDBM database
    char tmpl[] = "/tmp/gdbm_fuzzXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        perror("mkstemp");
        return 0;
    }
    close(fd);
    unlink(tmpl);

    // Open the GDBM database
    GDBM_FILE dbf = gdbm_open(tmpl, 512, GDBM_NEWDB, 0666, NULL);
    if (dbf == NULL) {
        fprintf(stderr, "Failed to open GDBM database\n");
        return 0;
    }

    // Prepare a key datum
    datum key;
    key.dptr = (char *)data;
    key.dsize = size;

    // Call the function-under-test
    datum value = gdbm_fetch(dbf, key);

    // Clean up
    if (value.dptr != NULL) {
        free(value.dptr);
    }
    gdbm_close(dbf);
    unlink(tmpl);

    return 0;
}