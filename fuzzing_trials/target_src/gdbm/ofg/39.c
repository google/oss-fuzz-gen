#include <gdbm.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

int LLVMFuzzerTestOneInput_39(const uint8_t *data, size_t size) {
    char tmpl[] = "/tmp/gdbm_fuzzXXXXXX";
    int fd;
    GDBM_FILE dbf;
    gdbm_count_t count;

    // Create a temporary file
    fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write fuzz data to the file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Close the file descriptor
    close(fd);

    // Open the GDBM database
    dbf = gdbm_open(tmpl, 512, GDBM_WRCREAT | GDBM_NOLOCK, 0666, NULL);
    if (dbf == NULL) {
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    gdbm_count(dbf, &count);

    // Close the database and remove the temporary file
    gdbm_close(dbf);
    unlink(tmpl);

    return 0;
}