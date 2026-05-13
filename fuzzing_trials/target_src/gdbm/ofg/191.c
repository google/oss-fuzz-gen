#include <gdbm.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

int LLVMFuzzerTestOneInput_191(const uint8_t *data, size_t size) {
    if (size < 1) return 0; // Ensure there's at least some data

    // Create a temporary file for the GDBM database
    char tmpl[] = "/tmp/gdbmfuzzXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) return 0;
    close(fd);
    unlink(tmpl);

    // Open the GDBM database
    GDBM_FILE dbf = gdbm_open(tmpl, 512, GDBM_WRCREAT, 0666, NULL);
    if (!dbf) return 0;

    // Prepare a datum structure with the fuzz data
    datum key;
    key.dptr = (char *)data;
    key.dsize = size;

    // Call the function-under-test
    gdbm_delete(dbf, key);

    // Close the GDBM database
    gdbm_close(dbf);

    // Clean up the temporary file
    unlink(tmpl);

    return 0;
}