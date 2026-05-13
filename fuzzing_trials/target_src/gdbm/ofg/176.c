#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int LLVMFuzzerTestOneInput_176(const uint8_t *data, size_t size) {
    char tmpl[] = "/tmp/fuzzdbXXXXXX";
    int fd;
    GDBM_FILE dbf;

    // Create a temporary file
    fd = mkstemp(tmpl);
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
        perror("gdbm_open");
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    gdbm_reorganize(dbf);

    // Close the GDBM file
    gdbm_close(dbf);

    // Remove the temporary file
    unlink(tmpl);

    return 0;
}