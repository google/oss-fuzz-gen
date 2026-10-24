#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int LLVMFuzzerTestOneInput_79(const uint8_t *data, size_t size) {
    char tmpl[] = "/tmp/fuzzdbXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        perror("mkstemp");
        return 0;
    }

    if (write(fd, data, size) != (ssize_t)size) {
        perror("write");
        close(fd);
        unlink(tmpl);
        return 0;
    }

    close(fd);

    GDBM_FILE dbf = gdbm_open(tmpl, 512, GDBM_WRCREAT, 0666, NULL);
    if (dbf != NULL) {
        gdbm_sync(dbf);
        gdbm_close(dbf);
    }

    unlink(tmpl);
    return 0;
}