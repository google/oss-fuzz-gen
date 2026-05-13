#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

int LLVMFuzzerTestOneInput_7(const uint8_t *data, size_t size) {
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);

    if (fd == -1) {
        perror("mkstemp");
        return 0;
    }

    if (write(fd, data, size) < size) {
        perror("write");
        close(fd);
        return 0;
    }

    close(fd);

    GDBM_FILE dbf = gdbm_open(tmpl, 512, GDBM_NEWDB, 0666, NULL);
    if (dbf != NULL) {
        gdbm_last_syserr(dbf);
        gdbm_close(dbf);
    }

    unlink(tmpl);

    return 0;
}