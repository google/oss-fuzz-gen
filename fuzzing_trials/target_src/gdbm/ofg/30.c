#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>

int LLVMFuzzerTestOneInput_30(const uint8_t *data, size_t size) {
    char tmpl[] = "/tmp/fuzzdbXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        perror("mkstemp");
        return 0;
    }

    if (write(fd, data, size) < size) {
        perror("write");
        close(fd);
        unlink(tmpl);
        return 0;
    }

    close(fd);

    GDBM_FILE dbf = gdbm_open(tmpl, 512, GDBM_WRCREAT, 0666, NULL);
    if (dbf == NULL) {
        unlink(tmpl);
        return 0;
    }

    // Fuzz the gdbm_convert function
    int flag = size % 2; // Use a simple flag derived from size
    gdbm_convert(dbf, flag);

    gdbm_close(dbf);
    unlink(tmpl);

    return 0;
}