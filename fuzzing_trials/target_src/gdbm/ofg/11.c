#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>

int LLVMFuzzerTestOneInput_11(const uint8_t *data, size_t size) {
    int fd;
    GDBM_FILE db;

    // Create a temporary file to use as a database
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    fd = mkstemp(tmpl);
    if (fd == -1) {
        perror("mkstemp");
        return 0;
    }

    // Write the fuzzing data to the temporary file
    if (write(fd, data, size) < size) {
        perror("write");
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Open the GDBM database using the temporary file
    db = gdbm_open(tmpl, 0, GDBM_WRCREAT, 0666, NULL);
    if (db == NULL) {
        perror("gdbm_open");
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    gdbm_avail_verify(db);

    // Clean up
    gdbm_close(db);
    close(fd);
    unlink(tmpl);

    return 0;
}