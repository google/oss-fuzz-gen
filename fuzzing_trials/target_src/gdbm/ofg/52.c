#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

int LLVMFuzzerTestOneInput_52(const uint8_t *data, size_t size) {
    char tmpl[] = "/tmp/fuzzgdbmXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        perror("mkstemp");
        return 0;
    }

    if (write(fd, data, size) != size) {
        perror("write");
        close(fd);
        unlink(tmpl);
        return 0;
    }

    close(fd);

    GDBM_FILE dbf = gdbm_open(tmpl, 512, GDBM_WRCREAT | GDBM_NOLOCK, 0666, NULL);
    if (dbf != NULL) {
        gdbm_needs_recovery(dbf);
        gdbm_close(dbf);
    }

    unlink(tmpl);
    return 0;
}