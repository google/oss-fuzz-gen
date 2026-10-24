#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gdbm/src/gdbm.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    int fd = open("./dummy_file", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd != -1) {
        write(fd, Data, Size);
        close(fd);
    }
}

int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size) {
    if (Size < 10) {
        return 0;
    }

    // Prepare dummy file
    write_dummy_file(Data, Size);

    // Open GDBM database

    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 2 of gdbm_open
    GDBM_FILE dbf = gdbm_open("./dummy_file", 512, GDBM_GETBLOCKSIZE, 0600, NULL);
    // End mutation: Producer.REPLACE_ARG_MUTATOR


    if (dbf == NULL) {
        return 0;
    }

    // Prepare key and value
    datum key, value;
    key.dptr = (char *)Data;
    key.dsize = Size / 2;
    value.dptr = (char *)(Data + Size / 2);
    value.dsize = Size - Size / 2;

    // Fuzz gdbm_store
    gdbm_store(dbf, key, value, GDBM_INSERT);

    // Fuzz gdbm_delete
    gdbm_delete(dbf, key);

    // Fuzz gdbm_convert

    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of gdbm_convert
    gdbm_convert(dbf, GDBM_READER);
    // End mutation: Producer.REPLACE_ARG_MUTATOR



    // Fuzz gdbm_last_syserr

    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function gdbm_last_syserr with gdbm_reorganize

    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function gdbm_reorganize with gdbm_avail_verify
    gdbm_avail_verify(dbf);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR


    // End mutation: Producer.REPLACE_FUNC_MUTATOR



    // Fuzz gdbm_sync

    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function gdbm_sync with gdbm_avail_verify
    gdbm_avail_verify(dbf);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR



    // Fuzz gdbm_exists
    gdbm_exists(dbf, key);

    // Close the database
    gdbm_close(dbf);

    return 0;
}