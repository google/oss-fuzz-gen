#include <gdbm.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>

int LLVMFuzzerTestOneInput_175(const uint8_t *data, size_t size) {
    char dbname[] = "/tmp/fuzzdbXXXXXX";
    int fd = mkstemp(dbname);
    if (fd == -1) {
        perror("mkstemp");
        return 0;
    }

    if (write(fd, data, size) != size) {
        perror("write");
        close(fd);
        unlink(dbname);
        return 0;
    }

    close(fd);

    GDBM_FILE dbf = gdbm_open(dbname, 512, GDBM_WRCREAT, 0666, NULL);
    if (dbf != NULL) {
        gdbm_reorganize(dbf);
        gdbm_close(dbf);
    }

    unlink(dbname);
    return 0;
}