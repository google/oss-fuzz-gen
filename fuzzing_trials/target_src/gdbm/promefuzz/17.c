// This fuzz driver is generated for library gdbm, aiming to fuzz the following functions:
// gdbm_last_errno at gdbmerrno.c:56:1 in gdbm.h
// gdbm_check_syserr at gdbmerrno.c:201:1 in gdbm.h
// gdbm_reorganize at gdbmreorg.c:31:1 in gdbm.h
// gdbm_errno_location at gdbmerrno.c:28:1 in gdbm.h
// gdbm_last_syserr at gdbmerrno.c:67:1 in gdbm.h
// gdbm_set_errno at gdbmerrno.c:37:1 in gdbm.h
// gdbm_open at gdbmopen.c:791:1 in gdbm.h
// gdbm_close at gdbmclose.c:28:1 in gdbm.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <gdbm.h>
#include <errno.h>

static void fuzz_gdbm_last_errno(GDBM_FILE dbf) {
    gdbm_last_errno(dbf);
}

static void fuzz_gdbm_check_syserr(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(gdbm_error)) return;
    gdbm_error err = *(gdbm_error *)Data;
    gdbm_check_syserr(err);
}

static void fuzz_gdbm_reorganize(GDBM_FILE dbf) {
    gdbm_reorganize(dbf);
}

static void fuzz_gdbm_errno_location() {
    gdbm_errno_location();
}

static void fuzz_gdbm_last_syserr(GDBM_FILE dbf) {
    gdbm_last_syserr(dbf);
}

static void fuzz_gdbm_set_errno(GDBM_FILE dbf, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(gdbm_error)) return;
    gdbm_error err = *(gdbm_error *)Data;
    gdbm_set_errno(dbf, err, 1);
}

int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size) {
    GDBM_FILE dbf = gdbm_open("./dummy_file", 512, GDBM_NEWDB, 0644, NULL);
    if (!dbf) {
        return 0;
    }

    fuzz_gdbm_last_errno(dbf);
    fuzz_gdbm_check_syserr(Data, Size);
    fuzz_gdbm_reorganize(dbf);
    fuzz_gdbm_errno_location();
    fuzz_gdbm_last_syserr(dbf);
    fuzz_gdbm_set_errno(dbf, Data, Size);

    gdbm_close(dbf);
    return 0;
}