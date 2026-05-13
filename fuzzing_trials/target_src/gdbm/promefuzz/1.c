// This fuzz driver is generated for library gdbm, aiming to fuzz the following functions:
// gdbm_open at gdbmopen.c:791:1 in gdbm.h
// gdbm_setopt at gdbmsetopt.c:417:1 in gdbm.h
// gdbm_last_errno at gdbmerrno.c:56:1 in gdbm.h
// gdbm_needs_recovery at gdbmerrno.c:78:1 in gdbm.h
// gdbm_convert at gdbmopen.c:933:1 in gdbm.h
// gdbm_set_errno at gdbmerrno.c:37:1 in gdbm.h
// gdbm_close at gdbmclose.c:28:1 in gdbm.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <gdbm.h>
#include <errno.h>

static GDBM_FILE create_dummy_db() {
    return gdbm_open("./dummy_file", 512, GDBM_NEWDB, 0666, NULL);
}

int LLVMFuzzerTestOneInput_1(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    GDBM_FILE dbf = create_dummy_db();
    if (!dbf) return 0;

    // Fuzz gdbm_setopt
    int option = Data[0] % 5; // Random option flag
    int value = (Size > 1) ? Data[1] : 0;
    gdbm_setopt(dbf, option, &value, sizeof(value));

    // Fuzz gdbm_last_errno
    gdbm_error last_err = gdbm_last_errno(dbf);

    // Fuzz gdbm_needs_recovery
    int needs_recovery = gdbm_needs_recovery(dbf);

    // Fuzz gdbm_convert
    int flag = (Size > 2) ? Data[2] % 2 : 0; // Random flag
    gdbm_convert(dbf, flag);

    // Fuzz gdbm_set_errno
    gdbm_error err_code = (Size > 3) ? Data[3] : 0; // Use arbitrary value for err_code
    int is_fatal = (Size > 4) ? Data[4] % 2 : 0;
    gdbm_set_errno(dbf, err_code, is_fatal);

    // Close the database
    gdbm_close(dbf);

    return 0;
}