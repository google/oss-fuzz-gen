#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

int LLVMFuzzerTestOneInput_104(const uint8_t *data, size_t size) {
    GDBM_FILE db;
    int fd;
    char tmpl[] = "/tmp/fuzzdbXXXXXX";

    // Create a temporary file to act as a database
    fd = mkstemp(tmpl);
    if (fd == -1) {
        perror("mkstemp");
        return 0;
    }

    // Write fuzz data to the temporary file
    if (write(fd, data, size) < size) {
        perror("write");
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Open the GDBM database
    db = gdbm_open(tmpl, 512, GDBM_WRCREAT, 0666, NULL);
    if (db == NULL) {
        perror("gdbm_open");
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    gdbm_error err = gdbm_last_errno(db);

    // Close the database and clean up
    gdbm_close(db);
    close(fd);
    unlink(tmpl);

    return 0;
}