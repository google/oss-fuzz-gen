#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gdbm/src/gdbm.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

// Helper function to create a GDBM_FILE for testing
static GDBM_FILE open_test_database() {
    GDBM_FILE dbf = gdbm_open("./dummy_file", 512, GDBM_WRCREAT | GDBM_NOLOCK, 0644, NULL);
    return dbf;
}

// Helper function to write dummy data to the database
static void write_dummy_data(GDBM_FILE dbf) {
    datum key, value;
    key.dptr = "key";
    key.dsize = strlen(key.dptr);
    value.dptr = "value";
    value.dsize = strlen(value.dptr);
    gdbm_store(dbf, key, value, GDBM_REPLACE);
}

int LLVMFuzzerTestOneInput_30(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    GDBM_FILE dbf = open_test_database();
    if (!dbf) return 0;

    write_dummy_data(dbf);

    datum key, result;
    key.dptr = (char *)Data;
    key.dsize = Size;

    // Test gdbm_firstkey
    datum first_key = gdbm_firstkey(dbf);
    if (first_key.dptr) {
        free(first_key.dptr);
    }

    // Test gdbm_nextkey
    datum next_key = gdbm_nextkey(dbf, key);
    if (next_key.dptr) {
        free(next_key.dptr);
    }

    // Test gdbm_fetch
    result = gdbm_fetch(dbf, key);
    if (result.dptr) {
        free(result.dptr);
    }

    // Test gdbm_clear_error
    gdbm_clear_error(dbf);

    // Test gdbm_delete
    gdbm_delete(dbf, key);

    // Test gdbm_exists
    gdbm_exists(dbf, key);

    gdbm_close(dbf);
    return 0;
}