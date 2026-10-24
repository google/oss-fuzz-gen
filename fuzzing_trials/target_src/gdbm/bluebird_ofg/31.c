#include "/src/gdbm/src/gdbm.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

// Removed 'extern "C"' as this is C code, not C++
int LLVMFuzzerTestOneInput_31(const uint8_t *data, size_t size) {
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from gdbm_open to gdbm_recover
    gdbm_recovery tawudefq;
    memset(&tawudefq, 0, sizeof(tawudefq));

    int ret_gdbm_recover_nodwj = gdbm_recover(dbf, &tawudefq, GDBM_INSERT);
    if (ret_gdbm_recover_nodwj < 0){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from gdbm_recover to gdbm_load
    int ret_escape_pcryn = escape(GDBM_GETMAXMAPSIZE);
    if (ret_escape_pcryn < 0){
    	return 0;
    }
    GDBM_FILE qezxdlgm;
    memset(&qezxdlgm, 0, sizeof(qezxdlgm));

    int ret_gdbm_load_ixoop = gdbm_load(&qezxdlgm, (const char *)"w", GDBM_SETMAXMAPSIZE, ret_escape_pcryn, (unsigned long *)&ret_gdbm_recover_nodwj);
    if (ret_gdbm_load_ixoop < 0){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR

    gdbm_load_from_file_ext(dbf, file, 0, 0, 0, &count);

    // Clean up

    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function gdbm_close with gdbm_reorganize
    gdbm_reorganize(dbf);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR


    fclose(file);
    unlink(tmpl);

    return 0;
}