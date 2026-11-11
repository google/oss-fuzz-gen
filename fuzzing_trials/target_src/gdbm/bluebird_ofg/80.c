#include "/src/gdbm/src/gdbm.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

// Removed 'extern "C"' as this is C code, not C++
int LLVMFuzzerTestOneInput_80(const uint8_t *data, size_t size) {
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from gdbm_open to gdbm_export

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from gdbm_open to gdbm_import

    int ret_gdbm_import_amthw = gdbm_import(dbf, (const char *)"r", GDBM_DEBUG_ENABLE);
    if (ret_gdbm_import_amthw < 0){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR

    char* ret_tildexpand_bdhvs = tildexpand((char *)"r");
    if (ret_tildexpand_bdhvs == NULL){
    	return 0;
    }
    int ret_yyparse_mbpfx = yyparse();
    if (ret_yyparse_mbpfx < 0){
    	return 0;
    }

    int ret_gdbm_export_juhwc = gdbm_export(dbf, ret_tildexpand_bdhvs, ret_yyparse_mbpfx, GDBM_NEWDB);
    if (ret_gdbm_export_juhwc < 0){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR

    gdbm_load_from_file_ext(dbf, file, 0, 0, 0, &count);

    // Clean up

    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function gdbm_close with gdbm_reorganize

    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function gdbm_reorganize with gdbm_needs_recovery
    gdbm_needs_recovery(dbf);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR


    // End mutation: Producer.REPLACE_FUNC_MUTATOR


    fclose(file);
    unlink(tmpl);

    return 0;
}