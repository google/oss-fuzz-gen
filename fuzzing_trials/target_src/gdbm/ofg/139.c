#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_139(const uint8_t *data, size_t size) {
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

    GDBM_FILE db = gdbm_open(tmpl, 512, GDBM_WRCREAT, 0644, NULL);
    if (db == NULL) {
        unlink(tmpl);
        return 0;
    }

    const char *error_message = gdbm_db_strerror(db);
    if (error_message != NULL) {
        printf("Error: %s\n", error_message);
    }

    gdbm_close(db);
    unlink(tmpl);

    return 0;
}