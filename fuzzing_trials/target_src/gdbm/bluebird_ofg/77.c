#include "/src/gdbm/src/gdbm.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "sys/syscall.h"

int LLVMFuzzerTestOneInput_77(const uint8_t *data, size_t size) {
    GDBM_FILE db;
    FILE *file;
    int flags = 0;

    // Create a temporary file to act as the GDBM database
    char dbname[] = "/tmp/gdbm_fuzz_dbXXXXXX";
    int db_fd = mkstemp(dbname);
    if (db_fd == -1) {
        perror("mkstemp");
        return 0;
    }

    // Write the fuzz data to the temporary database file
    if (write(db_fd, data, size) < size) {
        perror("write");
        close(db_fd);
        unlink(dbname);
        return 0;
    }

    // Open the GDBM database
    db = gdbm_fd_open(dbname, 512, GDBM_WRCREAT, 0666, NULL);
    if (db == NULL) {
        perror("gdbm_fd_open");
        close(db_fd);
        unlink(dbname);
        return 0;
    }

    // Create a temporary file to dump the database content
    char dump_filename[] = "/tmp/gdbm_fuzz_dumpXXXXXX";
    int dump_fd = mkstemp(dump_filename);
    if (dump_fd == -1) {
        perror("mkstemp");
        gdbm_close(db);
        close(db_fd);
        unlink(dbname);
        return 0;
    }

    // Open the dump file as a FILE* stream
    file = fdopen(dump_fd, "w");
    if (file == NULL) {
        perror("fdopen");
        gdbm_close(db);
        close(db_fd);
        unlink(dbname);
        close(dump_fd);
        unlink(dump_filename);
        return 0;
    }

    // Call the function-under-test
    gdbm_dump_to_file(db, file, flags);

    // Clean up
    fclose(file);
    gdbm_close(db);
    close(db_fd);
    unlink(dbname);
    close(dump_fd);
    unlink(dump_filename);

    return 0;
}