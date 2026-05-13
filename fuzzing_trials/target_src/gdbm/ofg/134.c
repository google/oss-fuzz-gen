#include <gdbm.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

int LLVMFuzzerTestOneInput_134(const uint8_t *data, size_t size) {
    // Create a temporary GDBM database file
    char db_filename[] = "/tmp/fuzz_gdbmXXXXXX";
    int db_fd = mkstemp(db_filename);
    if (db_fd == -1) {
        return 0;
    }
    close(db_fd);

    // Open the GDBM database
    GDBM_FILE db = gdbm_open(db_filename, 512, GDBM_NEWDB, 0666, NULL);
    if (!db) {
        unlink(db_filename);
        return 0;
    }

    // Create a temporary file for exporting
    char export_filename[] = "/tmp/fuzz_exportXXXXXX";
    int export_fd = mkstemp(export_filename);
    if (export_fd == -1) {
        gdbm_close(db);
        unlink(db_filename);
        return 0;
    }

    FILE *export_file = fdopen(export_fd, "wb");
    if (!export_file) {
        close(export_fd);
        gdbm_close(db);
        unlink(db_filename);
        unlink(export_filename);
        return 0;
    }

    // Call the function-under-test
    gdbm_export_to_file(db, export_file);

    // Clean up
    fclose(export_file);
    gdbm_close(db);
    unlink(db_filename);
    unlink(export_filename);

    return 0;
}