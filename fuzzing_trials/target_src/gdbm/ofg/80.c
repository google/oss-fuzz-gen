#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

int LLVMFuzzerTestOneInput_80(const uint8_t *data, size_t size) {
    GDBM_FILE db;
    int fd;
    char tmpl[] = "/tmp/gdbm_fuzzXXXXXX";
    char export_file[] = "/tmp/gdbm_exportXXXXXX";

    // Create a temporary file for the GDBM database
    fd = mkstemp(tmpl);
    if (fd == -1) {
        perror("mkstemp");
        return 0;
    }

    // Write the fuzz data to the database file
    if (write(fd, data, size) < size) {
        close(fd);
        perror("write");
        return 0;
    }

    // Close the file descriptor and open the GDBM database
    close(fd);
    db = gdbm_open(tmpl, 0, GDBM_WRCREAT, 0666, NULL);
    if (!db) {
        perror("gdbm_open");
        return 0;
    }

    // Create a temporary file for the export
    int export_fd = mkstemp(export_file);
    if (export_fd == -1) {
        perror("mkstemp");
        gdbm_close(db);
        return 0;
    }
    close(export_fd);

    // Call the function under test
    gdbm_export(db, export_file, 0, 0);

    // Clean up
    gdbm_close(db);
    unlink(tmpl);
    unlink(export_file);

    return 0;
}