#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <errno.h>

int LLVMFuzzerTestOneInput_101(const uint8_t *data, size_t size) {
    // Create a temporary file to act as the GDBM database
    char tmpl[] = "/tmp/gdbm_fuzzXXXXXX";
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

    // Close the file descriptor
    close(fd);

    // Open the GDBM database
    GDBM_FILE dbf = gdbm_open(tmpl, 512, GDBM_WRCREAT, 0666, NULL);
    if (dbf == NULL) {
        fprintf(stderr, "gdbm_open failed: %s\n", gdbm_strerror(gdbm_errno));
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    datum key = gdbm_firstkey(dbf);

    // Free the key if it is not NULL
    if (key.dptr != NULL) {
        free(key.dptr);
    }

    // Close the GDBM database
    gdbm_close(dbf);

    // Unlink the temporary file
    unlink(tmpl);

    return 0;
}