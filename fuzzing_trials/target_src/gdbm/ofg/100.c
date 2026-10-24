#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

int LLVMFuzzerTestOneInput_100(const uint8_t *data, size_t size) {
    char filename[] = "/tmp/gdbm_fuzz_XXXXXX";
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
    if (dbf == NULL) {
        unlink(filename);
        return 0;
    }

    datum first_key = gdbm_firstkey(dbf);
    if (first_key.dptr != NULL) {
        free(first_key.dptr);
    }

    gdbm_close(dbf);
    unlink(filename);

    return 0;
}