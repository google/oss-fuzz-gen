#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gdbm/src/gdbm.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static GDBM_FILE initialize_gdbm_file(const uint8_t *Data, size_t Size) {
    // Create a dummy file for gdbm_open
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) {
        return NULL;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    // Open the GDBM file
    return gdbm_open("./dummy_file", 512, GDBM_WRCREAT, 0666, NULL);
}

int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Initialize GDBM file
    GDBM_FILE dbf = initialize_gdbm_file(Data, Size);
    if (!dbf) {
        return 0;
    }

    // Fuzz gdbm_needs_recovery

    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function gdbm_needs_recovery with gdbm_fdesc
    int needs_recovery = gdbm_fdesc(dbf);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR



    // Fuzz gdbm_reorganize
    if (needs_recovery) {
        gdbm_reorganize(dbf);
    }

    // Fuzz gdbm_clear_error
    gdbm_clear_error(dbf);

    // Fuzz gdbm_set_errno with arbitrary values

    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of gdbm_set_errno

    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of gdbm_set_errno
    gdbm_set_errno(dbf, _GDBM_MIN_ERRNO, Data[0] % 2);
    // End mutation: Producer.REPLACE_ARG_MUTATOR


    // End mutation: Producer.REPLACE_ARG_MUTATOR



    // Fuzz gdbm_copy_meta using the same dbf as both source and destination
    gdbm_copy_meta(dbf, dbf);

    // Close the GDBM file

    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function gdbm_close with gdbm_sync

    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function gdbm_sync with gdbm_last_syserr
    gdbm_last_syserr(dbf);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR


    // End mutation: Producer.REPLACE_FUNC_MUTATOR



    // Clean up the dummy file
    remove("./dummy_file");

    return 0;
}