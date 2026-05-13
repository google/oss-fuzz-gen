#include "/src/gdbm/src/gdbm.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "sys/syscall.h"
#include <fcntl.h>

int LLVMFuzzerTestOneInput_64(const uint8_t *data, size_t size) {
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
    db = gdbm_open(tmpl, 0, GDBM_WRCREAT, 0666, NULL);
    if (db == NULL) {
        fprintf(stderr, "Failed to open GDBM database\n");
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Create another temporary file to dump the database
    char dumpfile[] = "/tmp/dumpfileXXXXXX";

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from gdbm_open to gdbm_convert

    int ret_gdbm_convert_mbrof = gdbm_convert(db, GDBM_VERSION_PATCH);
    if (ret_gdbm_convert_mbrof < 0){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR

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

    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 2 of gdbm_dump_to_file

    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 2 of gdbm_dump_to_file
    gdbm_dump_to_file(db, file, GDBM_SETCOALESCEBLKS);
    // End mutation: Producer.REPLACE_ARG_MUTATOR


    // End mutation: Producer.REPLACE_ARG_MUTATOR



    // Clean up
    fclose(file);
    gdbm_close(db);
    close(fd);
    unlink(tmpl);
    unlink(dumpfile);

    return 0;
}