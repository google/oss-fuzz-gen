#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int LLVMFuzzerTestOneInput_31(const uint8_t *data, size_t size) {
    char tmpl[] = "/tmp/fuzzdbXXXXXX";
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

    GDBM_FILE dbf = gdbm_open(tmpl, 512, GDBM_WRCREAT, 0666, NULL);
    if (dbf == NULL) {
        perror("gdbm_open");
        unlink(tmpl);
        return 0;
    }

    int flags[] = {GDBM_FAST, GDBM_SYNC, GDBM_NOLOCK, GDBM_CLOEXEC};
    size_t num_flags = sizeof(flags) / sizeof(flags[0]);

    for (size_t i = 0; i < num_flags; ++i) {
        gdbm_convert(dbf, flags[i]);
    }

    gdbm_close(dbf);
    unlink(tmpl);
    return 0;
}