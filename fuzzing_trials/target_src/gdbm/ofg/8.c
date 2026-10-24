#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syscall.h>
#include <sys/types.h>

int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    char filename[] = "/tmp/fuzzdbXXXXXX";
    int fd;
    GDBM_FILE dbf;

    // Create a temporary file
    fd = mkstemp(filename);
    if (fd == -1) {
        perror("mkstemp");
        return 0;
    }

    // Write the fuzz data to the file
    if (write(fd, data, size) < size) {
        perror("write");
        close(fd);
        unlink(filename);
        return 0;
    }

    // Close the file descriptor
    close(fd);

    // Open the GDBM database
    dbf = gdbm_open(filename, 512, GDBM_WRCREAT | GDBM_NOLOCK, 0644, NULL);
    if (dbf == NULL) {
        perror("gdbm_open");
        unlink(filename);
        return 0;
    }

    // Call the function-under-test
    int result = gdbm_last_syserr(dbf);

    // Close the GDBM database
    gdbm_close(dbf);

    // Remove the temporary file
    unlink(filename);

    return 0;
}