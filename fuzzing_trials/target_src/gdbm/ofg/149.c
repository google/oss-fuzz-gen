#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_149(const uint8_t *data, size_t size) {
    char filename[] = "/tmp/fuzzdbXXXXXX";
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

    GDBM_FILE dbf = gdbm_open(filename, 512, GDBM_NEWDB, 0666, NULL);
    if (dbf != NULL) {
        gdbm_close(dbf);
    }

    unlink(filename);
    return 0;
}