#include "/src/gdbm/src/gdbm.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "sys/syscall.h"
#include <fcntl.h>

int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    GDBM_FILE db;
    FILE *file;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd;

    // Create a temporary file for the GDBM database
    fd = mkstemp(tmpl);
    if (fd == -1) {
        perror("mkstemp");
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) < size) {
        perror("write");
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Open the GDBM database

    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 2 of gdbm_open
    db = gdbm_open(tmpl, 0, 64, 0666, NULL);
    // End mutation: Producer.REPLACE_ARG_MUTATOR


    if (db == NULL) {
        fprintf(stderr, "Failed to open GDBM database\n");
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Create another temporary file to dump the database
    char dumpfile[] = "/tmp/dumpfileXXXXXX";
    int dump_fd = mkstemp(dumpfile);
    if (dump_fd == -1) {
        perror("mkstemp for dumpfile");
        gdbm_close(db);
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Open the dump file as a FILE* stream
    file = fdopen(dump_fd, "w+");
    if (file == NULL) {
        perror("fdopen");
        gdbm_close(db);
        close(fd);
        close(dump_fd);
        unlink(tmpl);
        unlink(dumpfile);
        return 0;
    }

    // Call the function under test
    gdbm_dump_to_file(db, file, 0);

    // Clean up
    fclose(file);
    gdbm_close(db);
    close(fd);
    unlink(tmpl);
    unlink(dumpfile);

    return 0;
}