#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_148(const uint8_t *data, size_t size) {
    char tmpl[] = "/tmp/fuzzdbXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        perror("mkstemp");
        return 0;
    }

    // Write fuzz data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        perror("write");
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Open the GDBM database
    GDBM_FILE dbf = gdbm_open(tmpl, 512, GDBM_WRCREAT, 0644, NULL);
    if (dbf == NULL) {
        perror("gdbm_open");
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Close the GDBM database
    gdbm_close(dbf);

    // Clean up
    close(fd);
    unlink(tmpl);

    return 0;
}