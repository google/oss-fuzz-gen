#include "/src/gdbm/src/gdbm.h"
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

int LLVMFuzzerTestOneInput_28(const uint8_t *data, size_t size) {
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
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

    GDBM_FILE dbf = gdbm_open(tmpl, 0, GDBM_WRCREAT | GDBM_NOLOCK, 0666, NULL);
    if (dbf == NULL) {
        unlink(tmpl);
        return 0;
    }

    gdbm_count_t count;
    gdbm_count(dbf, &count);

    gdbm_close(dbf);
    unlink(tmpl);

    return 0;
}