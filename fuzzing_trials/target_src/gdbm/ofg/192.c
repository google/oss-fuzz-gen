#include <gdbm.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_192(const uint8_t *data, size_t size) {
    // Create a temporary file to act as the GDBM database
    char tmpl[] = "/tmp/gdbm_fuzzXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    close(fd);

    // Open the GDBM database
    GDBM_FILE dbf = gdbm_open(tmpl, 512, GDBM_WRCREAT | GDBM_NOLOCK, 0644, NULL);
    if (dbf == NULL) {
        unlink(tmpl);
        return 0;
    }

    // Prepare a datum for the key
    datum key;
    key.dptr = (char *)data;
    key.dsize = size > 0 ? size : 1; // Ensure dsize is not zero

    // Call the function-under-test
    gdbm_delete(dbf, key);

    // Clean up
    gdbm_close(dbf);
    unlink(tmpl);

    return 0;
}