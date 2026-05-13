#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_137(const uint8_t *data, size_t size) {
    GDBM_FILE dbf;
    gdbm_recovery recovery;
    int flags = 0; // Use default flags for recovery

    // Create a temporary file to use as a GDBM database
    char tmpl[] = "/tmp/gdbm_fuzzXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        perror("mkstemp");
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        perror("write");
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Close the file descriptor
    close(fd);

    // Open the GDBM file
    dbf = gdbm_open(tmpl, 0, GDBM_WRCREAT, 0666, NULL);
    if (dbf == NULL) {
        fprintf(stderr, "Failed to open GDBM file: %s\n", gdbm_strerror(gdbm_errno));
        unlink(tmpl);
        return 0;
    }

    // Initialize the recovery structure
    memset(&recovery, 0, sizeof(recovery));

    // Call the function-under-test
    gdbm_recover(dbf, &recovery, flags);

    // Close the GDBM file
    gdbm_close(dbf);

    // Remove the temporary file
    unlink(tmpl);

    return 0;
}