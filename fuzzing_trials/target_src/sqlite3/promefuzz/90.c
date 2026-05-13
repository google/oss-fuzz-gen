// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_str_vappendf at sqlite3.c:18156:17 in sqlite3.h
// sqlite3_open at sqlite3.c:174695:16 in sqlite3.h
// sqlite3_str_new at sqlite3.c:19257:25 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
// sqlite3_str_appendall at sqlite3.c:19111:17 in sqlite3.h
// sqlite3_str_value at sqlite3.c:19202:18 in sqlite3.h
// sqlite3_str_finish at sqlite3.c:19172:18 in sqlite3.h
// sqlite3_free at sqlite3.c:17452:17 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include "sqlite3.h"

static void fuzz_sqlite3_str_appendf(sqlite3_str *pStr, const char *zFormat, ...) {
    va_list args;
    va_start(args, zFormat);
    sqlite3_str_vappendf(pStr, zFormat, args);
    va_end(args);
}

int LLVMFuzzerTestOneInput_90(const unsigned char *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize SQLite
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        return 0;
    }

    // Create a new dynamic string object
    sqlite3_str *pStr = sqlite3_str_new(db);
    if (!pStr) {
        sqlite3_close(db);
        return 0;
    }

    // Append formatted text to the string object
    fuzz_sqlite3_str_appendf(pStr, "%.*s", (int)Size, Data);

    // Safely append all data to the string object
    char *safeData = (char *)malloc(Size + 1);
    if (safeData) {
        memcpy(safeData, Data, Size);
        safeData[Size] = '\0'; // Ensure null-termination
        sqlite3_str_appendall(pStr, safeData);
        free(safeData);
    }

    // Retrieve current value of the string
    char *value = sqlite3_str_value(pStr);
    if (value) {
        printf("Value: %s\n", value);
    }

    // Finalize the string object and free the result
    char *finishedStr = sqlite3_str_finish(pStr);
    if (finishedStr) {
        sqlite3_free(finishedStr);
    }

    // Close the SQLite database
    sqlite3_close(db);

    return 0;
}
    #ifdef INC_MAIN
    #include <stdio.h>
    #include <stdlib.h>
    #include <stdint.h>
    int main(int argc, char *argv[])
    {
        FILE *f;
        uint8_t *data = NULL;
        long size;

        if(argc < 2)
            exit(0);

        f = fopen(argv[1], "rb");
        if(f == NULL)
            exit(0);

        fseek(f, 0, SEEK_END);

        size = ftell(f);
        rewind(f);

        if(size < 1 + 1)
            exit(0);

        data = (uint8_t *)malloc((size_t)size);
        if(data == NULL)
            exit(0);

        if(fread(data, (size_t)size, 1, f) != 1)
            exit(0);

        LLVMFuzzerTestOneInput_90(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    