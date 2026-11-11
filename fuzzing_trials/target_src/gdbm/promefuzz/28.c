// This fuzz driver is generated for library gdbm, aiming to fuzz the following functions:
// vlerror at lex.c:2636:1 in gdbmtool.h
// gdbm_strerror at gdbmerrno.c:151:1 in gdbm.h
// gdbm_db_strerror at gdbmerrno.c:159:1 in gdbm.h
// dberror at gram.c:2319:1 in gdbmtool.h
// terror at gram.c:2308:1 in gdbmtool.h
// lerror at lex.c:2650:1 in gdbmtool.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <gdbm.h>
#include <gdbmtool.h>

static void dummy_fatal_err(const char *msg) {
    fprintf(stderr, "Fatal error: %s\n", msg);
}

static void setup_dummy_gdbm_file(GDBM_FILE dbf) {
    dbf->name = "./dummy_file";
    dbf->last_error = 0;
    dbf->last_syserror = 0;
    dbf->last_errstr = NULL;
    dbf->fatal_err = dummy_fatal_err;
}

static void test_vlerror(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vlerror(NULL, fmt, args);
    va_end(args);
}

int LLVMFuzzerTestOneInput_28(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(gdbm_error)) return 0;
    
    gdbm_error err_code = *((gdbm_error *)Data);
    const char *error_str = gdbm_strerror(err_code);
    fprintf(stderr, "Error string: %s\n", error_str);

    GDBM_FILE dbf = (GDBM_FILE)malloc(sizeof(struct gdbm_file_info));
    if (!dbf) return 0;
    setup_dummy_gdbm_file(dbf);
    
    const char *db_error_str = gdbm_db_strerror(dbf);
    fprintf(stderr, "DB Error string: %s\n", db_error_str);

    test_vlerror("Test error message: %s", error_str);

    dberror("Database error: %s", error_str);
    terror("Test terror message: %s", error_str);

    struct locus loc;
    struct point beg = { .file = "dummy_file", .line = 1, .col = 1 };
    struct point end = { .file = "dummy_file", .line = 1, .col = 10 };
    loc.beg = beg;
    loc.end = end;

    lerror(&loc, "Location error: %s", error_str);

    free(dbf);
    return 0;
}