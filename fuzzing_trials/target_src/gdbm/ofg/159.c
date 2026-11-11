#include <gdbm.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_159(const uint8_t *data, size_t size) {
    // Ensure there is enough data to work with
    if (size < 2) return 0;

    // Create a temporary database file
    char tmpl[] = "/tmp/gdbmfuzzXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) return 0;
    close(fd);

    // Open the GDBM database
    GDBM_FILE db = gdbm_open(tmpl, 512, GDBM_NEWDB, 0666, NULL);
    if (!db) {
        unlink(tmpl);
        return 0;
    }

    // Prepare the key and value
    datum key;
    datum value;
    int flag = data[0] % 2; // Choose a flag based on the first byte

    key.dptr = (char *)data;
    key.dsize = size / 2;

    value.dptr = (char *)(data + size / 2);
    value.dsize = size - size / 2;

    // Call the function-under-test
    gdbm_store(db, key, value, flag);

    // Clean up
    gdbm_close(db);
    unlink(tmpl);

    return 0;
}