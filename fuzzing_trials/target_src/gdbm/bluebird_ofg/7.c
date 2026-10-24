#include "/src/gdbm/src/gdbm.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_7(const uint8_t *data, size_t size) {
    // Ensure the size is large enough to split into two strings
    if (size < 2) return 0;

    // Create a temporary GDBM database file
    char tmpl[] = "/tmp/fuzzgdbmXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        perror("mkstemp");
        return 0;
    }
    close(fd);

    GDBM_FILE db = gdbm_open(tmpl, 512, GDBM_WRCREAT | GDBM_NOLOCK, 0666, NULL);
    if (!db) {
        unlink(tmpl);
        return 0;
    }

    // Split the input data into two strings
    size_t split_point = size / 2;
    char *str1 = (char *)malloc(split_point + 1);
    char *str2 = (char *)malloc(size - split_point + 1);

    if (!str1 || !str2) {
        if (str1) free(str1);
        if (str2) free(str2);
        gdbm_close(db);
        unlink(tmpl);
        return 0;
    }

    memcpy(str1, data, split_point);
    str1[split_point] = '\0';
    memcpy(str2, data + split_point, size - split_point);
    str2[size - split_point] = '\0';

    // Call the function-under-test
    gdbm_failure_atomic(db, str1, str2);

    // Clean up
    free(str1);
    free(str2);
    gdbm_close(db);
    unlink(tmpl);

    return 0;
}