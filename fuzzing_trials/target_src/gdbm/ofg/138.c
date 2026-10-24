#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_138(const uint8_t *data, size_t size) {
    // Create a temporary file to use with GDBM
    char tmpl[] = "/tmp/gdbmfileXXXXXX";
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

    // Open the GDBM database
    GDBM_FILE dbf = gdbm_open(tmpl, 512, GDBM_WRCREAT, 0666, NULL);
    if (dbf == NULL) {
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    const char *error_message = gdbm_db_strerror(dbf);

    // Print the error message (for debugging purposes)
    printf("GDBM error message: %s\n", error_message);

    // Close the GDBM database
    gdbm_close(dbf);

    // Remove the temporary file
    unlink(tmpl);

    return 0;
}