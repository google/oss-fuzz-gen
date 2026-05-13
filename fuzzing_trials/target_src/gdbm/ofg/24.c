#include <gdbm.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_24(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    // Create a temporary file for the GDBM database
    char tmpl[] = "/tmp/fuzzdbXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) return 0;

    // Open the GDBM database
    GDBM_FILE db = gdbm_open(tmpl, 0, GDBM_NEWDB, 0666, NULL);
    if (!db) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Prepare the initial key datum
    datum initial_key;
    initial_key.dptr = (char *)data;
    initial_key.dsize = size;

    // Call the function-under-test
    datum next_key = gdbm_nextkey(db, initial_key);

    // Clean up
    if (next_key.dptr) {
        free(next_key.dptr);
    }
    gdbm_close(db);
    close(fd);
    unlink(tmpl);

    return 0;
}