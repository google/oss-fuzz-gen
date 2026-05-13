#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_136(const uint8_t *data, size_t size) {
    char filename[] = "/tmp/fuzzdbXXXXXX";
    int fd = mkstemp(filename);
    if (fd == -1) {
        perror("mkstemp");
        return 0;
    }

    if (write(fd, data, size) < size) {
        perror("write");
        close(fd);
        unlink(filename);
        return 0;
    }

    close(fd);

    GDBM_FILE dbf = gdbm_open(filename, 512, GDBM_WRCREAT, 0666, NULL);
    if (!dbf) {
        unlink(filename);
        return 0;
    }

    gdbm_recovery recovery;
    memset(&recovery, 0, sizeof(recovery));

    int flags = 0; // Try different flag values for variations
    gdbm_recover(dbf, &recovery, flags);

    gdbm_close(dbf);
    unlink(filename);

    return 0;
}