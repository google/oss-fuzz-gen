#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>

int LLVMFuzzerTestOneInput_152(const uint8_t *data, size_t size) {
    char filename[] = "/tmp/gdbmfuzzXXXXXX";
    int fd = mkstemp(filename);
    if (fd == -1) {
        perror("mkstemp");
        return 0;
    }

    if (write(fd, data, size) != size) {
        perror("write");
        close(fd);
        unlink(filename);
        return 0;
    }

    close(fd);

    GDBM_FILE dbf = gdbm_open(filename, 512, GDBM_WRCREAT, 0666, NULL);
    if (dbf != NULL) {
        gdbm_fdesc(dbf);
        gdbm_close(dbf);
    }

    unlink(filename);
    return 0;
}