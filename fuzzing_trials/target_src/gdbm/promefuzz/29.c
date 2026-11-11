// This fuzz driver is generated for library gdbm, aiming to fuzz the following functions:
// pager_printf at pagerfile.c:160:1 in gdbmtool.h
// pager_writeln at pagerfile.c:102:1 in gdbmtool.h
// pager_open at pagerfile.c:190:1 in gdbmtool.h
// pager_close at pagerfile.c:172:1 in gdbmtool.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include "gdbmtool.h"

static void fuzz_pager_printf(PAGERFILE *pfp, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;
    char *fmt = (char *)malloc(Size + 1);
    if (!fmt) return;
    memcpy(fmt, Data, Size);
    fmt[Size] = '\0';

    // Ensure the format string is valid by replacing any '%' with '%%'
    for (size_t i = 0; i < Size; ++i) {
        if (fmt[i] == '%') {
            fmt[i] = ' ';
        }
    }

    pager_printf(pfp, fmt);
    free(fmt);
}

static void fuzz_pager_writeln(PAGERFILE *pfp, const uint8_t *Data, size_t Size) {
    char *str = (char *)malloc(Size + 1);
    if (!str) return;
    memcpy(str, Data, Size);
    str[Size] = '\0';

    pager_writeln(pfp, str);
    free(str);
}

int LLVMFuzzerTestOneInput_29(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    FILE *dummy_file = fopen("./dummy_file", "w+");
    if (!dummy_file) return 0;

    PAGERFILE *pfp = pager_open(dummy_file, 10, "less");
    if (!pfp) {
        fclose(dummy_file);
        return 0;
    }

    fuzz_pager_printf(pfp, Data, Size);
    fuzz_pager_writeln(pfp, Data, Size);

    pager_close(pfp);
    fclose(dummy_file);

    return 0;
}