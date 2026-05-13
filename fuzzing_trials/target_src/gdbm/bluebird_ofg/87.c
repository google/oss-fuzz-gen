#include "/src/gdbm/src/gdbm.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

// Removed 'extern "C"' as this is C code, not C++
int LLVMFuzzerTestOneInput_87(const uint8_t *data, size_t size) {
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
    gdbm_load_from_file_ext(dbf, file, 0, 0, 0, &count);

    // Clean up

    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function gdbm_close with gdbm_reorganize

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from gdbm_load_from_file_ext to unescape

    int ret_unescape_gpnrk = unescape((int )count);
    if (ret_unescape_gpnrk < 0){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from unescape to gdbm_load_from_file
    gdbm_error ret_gdbm_last_errno_eqkzp = gdbm_last_errno(0);
    if (ret_gdbm_last_errno_eqkzp < 0){
    	return 0;
    }

    int ret_gdbm_load_from_file_bvwlg = gdbm_load_from_file(NULL, file, GDBM_CACHE_AUTO, ret_unescape_gpnrk, (unsigned long *)&ret_gdbm_last_errno_eqkzp);
    if (ret_gdbm_load_from_file_bvwlg < 0){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR

    gdbm_reorganize(dbf);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR


    fclose(file);
    unlink(tmpl);

    return 0;
}