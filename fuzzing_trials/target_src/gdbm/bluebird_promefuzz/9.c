#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include "/src/gdbm/src/gdbm.h"
#include "gdbmtool.h"

static void prepare_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fputs("dummy data", file);
        fclose(file);
    }
}

static void fuzz_vlerror(struct locus const *loc, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vlerror(loc, fmt, ap);
    va_end(ap);
}

int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size) {
    prepare_dummy_file();

    // Fuzz gdbm_strerror
    if (Size >= sizeof(gdbm_error)) {
        gdbm_error err_code;
        memcpy(&err_code, Data, sizeof(gdbm_error));
        const char *err_str = gdbm_strerror(err_code);
        if (err_str) {
            printf("Error String: %s\n", err_str);
        }
    }

    // Fuzz gdbm_clear_error
    GDBM_FILE dbf = gdbm_open("./dummy_file", 512, GDBM_WRCREAT, 0666, NULL);
    if (dbf) {
        gdbm_clear_error(dbf);
        gdbm_close(dbf);
    }

    // Fuzz dberror
    dberror("Test error with code: %d", Size);

    // Fuzz lerror
    struct locus loc = {{"dummy_file", 1, 1}, {"dummy_file", 1, 10}};
    lerror(&loc, "Test locus error with code: %d", Size);

    // Fuzz vlerror
    fuzz_vlerror(&loc, "Test vlerror with code: %d", Size);

    // Fuzz terror
    terror("Test terror with code: %d", Size);

    return 0;
}