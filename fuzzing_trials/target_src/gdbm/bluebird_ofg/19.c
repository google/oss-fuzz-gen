#include "/src/gdbm/src/gdbm.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

// Removed 'extern "C"' as this is C code, not C++
int LLVMFuzzerTestOneInput_19(const uint8_t *data, size_t size) {
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        perror("mkstemp");
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        perror("write");
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Rewind the file descriptor to the beginning
    if (lseek(fd, 0, SEEK_SET) == -1) {
        perror("lseek");
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Open the file as a FILE* stream
    FILE *file = fdopen(fd, "rb");
    if (!file) {
        perror("fdopen");
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Initialize GDBM_FILE
    GDBM_FILE dbf = gdbm_open(tmpl, 512, GDBM_WRCREAT, 0666, NULL);
    if (!dbf) {
        perror("gdbm_open");
        fclose(file);
        unlink(tmpl);
        return 0;
    }

    // Initialize the unsigned long pointer
    unsigned long count = 0;

    // Call the function-under-test

    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 3 of gdbm_load_from_file_ext

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from gdbm_open to gdbm_bucket_count
    size_t rfhifllr = 0;

    int ret_gdbm_bucket_count_jfsxp = gdbm_bucket_count(dbf, &rfhifllr);
    if (ret_gdbm_bucket_count_jfsxp < 0){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR

    gdbm_load_from_file_ext(dbf, file, 0, 0, 0, &count);
    // End mutation: Producer.REPLACE_ARG_MUTATOR



    // Clean up

    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function gdbm_close with gdbm_reorganize
    gdbm_reorganize(dbf);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR


    fclose(file);
    unlink(tmpl);

    return 0;
}