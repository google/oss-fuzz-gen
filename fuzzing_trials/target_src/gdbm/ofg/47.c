#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

int LLVMFuzzerTestOneInput_47(const uint8_t *data, size_t size) {
    if (size < 3) return 0; // Ensure there is enough data for the test

    // Create a temporary database file
    char db_filename[] = "/tmp/gdbm_fuzz_dbXXXXXX";
    int db_fd = mkstemp(db_filename);
    if (db_fd == -1) {
        perror("mkstemp");
        return 0;
    }
    close(db_fd);

    // Open the GDBM database
    GDBM_FILE dbf = gdbm_open(db_filename, 512, GDBM_WRCREAT, 0666, NULL);
    if (!dbf) {
        unlink(db_filename);
        return 0;
    }

    // Prepare strings from the input data
    size_t str1_len = data[0] % (size - 2) + 1;
    size_t str2_len = data[1] % (size - 2 - str1_len) + 1;

    char *str1 = (char *)malloc(str1_len + 1);
    char *str2 = (char *)malloc(str2_len + 1);

    if (!str1 || !str2) {
        gdbm_close(dbf);
        unlink(db_filename);
        free(str1);
        free(str2);
        return 0;
    }

    memcpy(str1, data + 2, str1_len);
    memcpy(str2, data + 2 + str1_len, str2_len);
    str1[str1_len] = '\0';
    str2[str2_len] = '\0';

    // Store the key-value pair in the database
    datum key, value;
    key.dptr = str1;
    key.dsize = str1_len;
    value.dptr = str2;
    value.dsize = str2_len;

    gdbm_store(dbf, key, value, GDBM_REPLACE);

    // Clean up
    gdbm_close(dbf);
    unlink(db_filename);
    free(str1);
    free(str2);

    return 0;
}