#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int LLVMFuzzerTestOneInput_135(const uint8_t *data, size_t size) {
    // Create a temporary file to act as the GDBM database
    char db_template[] = "/tmp/fuzzdbXXXXXX";
    int db_fd = mkstemp(db_template);
    if (db_fd == -1) {
        perror("mkstemp");
        return 0;
    }

    // Write the fuzz data to the temporary GDBM file
    if (write(db_fd, data, size) != (ssize_t)size) {
        perror("write");
        close(db_fd);
        unlink(db_template);
        return 0;
    }

    // Open the GDBM file
    GDBM_FILE dbf = gdbm_open(db_template, 512, GDBM_WRCREAT, 0666, NULL);
    if (dbf == NULL) {
        perror("gdbm_open");
        close(db_fd);
        unlink(db_template);
        return 0;
    }

    // Create a temporary file to export the GDBM data to
    char export_template[] = "/tmp/exportXXXXXX";
    int export_fd = mkstemp(export_template);
    if (export_fd == -1) {
        perror("mkstemp");
        gdbm_close(dbf);
        close(db_fd);
        unlink(db_template);
        return 0;
    }

    FILE *export_file = fdopen(export_fd, "wb");
    if (export_file == NULL) {
        perror("fdopen");
        gdbm_close(dbf);
        close(db_fd);
        unlink(db_template);
        close(export_fd);
        unlink(export_template);
        return 0;
    }

    // Call the function-under-test
    gdbm_export_to_file(dbf, export_file);

    // Clean up
    fclose(export_file);
    gdbm_close(dbf);
    close(db_fd);
    unlink(db_template);
    unlink(export_template);

    return 0;
}