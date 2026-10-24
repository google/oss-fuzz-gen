#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_81(const uint8_t *data, size_t size) {
    // Create a temporary file to use as the GDBM database
    char db_template[] = "/tmp/gdbm_fuzz_dbXXXXXX";
    int db_fd = mkstemp(db_template);
    if (db_fd == -1) {
        perror("mkstemp");
        return 0;
    }
    close(db_fd);

    // Open the GDBM database
    GDBM_FILE dbf = gdbm_open(db_template, 512, GDBM_WRCREAT, 0666, NULL);
    if (!dbf) {
        perror("gdbm_open");
        unlink(db_template);
        return 0;
    }

    // Create a temporary file to use as the export file
    char export_template[] = "/tmp/gdbm_exportXXXXXX";
    int export_fd = mkstemp(export_template);
    if (export_fd == -1) {
        perror("mkstemp");
        gdbm_close(dbf);
        unlink(db_template);
        return 0;
    }
    close(export_fd);

    // Use the first byte of data to determine the flags for gdbm_export
    int flags = (size > 0) ? data[0] : 0;

    // Call the function-under-test
    gdbm_export(dbf, export_template, flags, 0);

    // Clean up
    gdbm_close(dbf);
    unlink(db_template);
    unlink(export_template);

    return 0;
}