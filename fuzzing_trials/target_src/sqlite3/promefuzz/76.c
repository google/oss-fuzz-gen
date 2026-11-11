// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_malloc at sqlite3.c:17377:18 in sqlite3.h
// sqlite3_complete16 at sqlite3.c:170900:16 in sqlite3.h
// sqlite3_free at sqlite3.c:17452:17 in sqlite3.h
// sqlite3_malloc at sqlite3.c:17377:18 in sqlite3.h
// sqlite3_complete at sqlite3.c:170735:16 in sqlite3.h
// sqlite3_free at sqlite3.c:17452:17 in sqlite3.h
// sqlite3_initialize at sqlite3.c:171208:16 in sqlite3.h
// sqlite3_open at sqlite3.c:174695:16 in sqlite3.h
// sqlite3_drop_modules at sqlite3.c:145728:16 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
// sqlite3_malloc at sqlite3.c:17377:18 in sqlite3.h
// sqlite3_realloc at sqlite3.c:17623:18 in sqlite3.h
// sqlite3_free at sqlite3.c:17452:17 in sqlite3.h
// sqlite3_malloc at sqlite3.c:17377:18 in sqlite3.h
// sqlite3_free at sqlite3.c:17452:17 in sqlite3.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sqlite3.h>
#include <string.h>

static void fuzz_sqlite3_complete16(const uint8_t *Data, size_t Size) {
    // Ensure the input data is a multiple of 2 for UTF-16 encoding
    if (Size % 2 != 0) return;

    // Null-terminate the input data for UTF-16
    uint16_t *utf16_sql = (uint16_t *)sqlite3_malloc(Size + 2);
    if (!utf16_sql) return;
    memcpy(utf16_sql, Data, Size);
    utf16_sql[Size / 2] = 0;

    // Call the target function
    sqlite3_complete16(utf16_sql);

    // Free allocated memory
    sqlite3_free(utf16_sql);
}

static void fuzz_sqlite3_complete(const uint8_t *Data, size_t Size) {
    // Null-terminate the input data for UTF-8
    char *utf8_sql = (char *)sqlite3_malloc(Size + 1);
    if (!utf8_sql) return;
    memcpy(utf8_sql, Data, Size);
    utf8_sql[Size] = '\0';

    // Call the target function
    sqlite3_complete(utf8_sql);

    // Free allocated memory
    sqlite3_free(utf8_sql);
}

static void fuzz_sqlite3_drop_modules(const uint8_t *Data, size_t Size) {
    // Initialize SQLite
    if (sqlite3_initialize() != SQLITE_OK) return;

    // Create a dummy database connection
    sqlite3 *db;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return;

    // Prepare a keep list
    const char *azKeep[] = { "module1", "module2", NULL };

    // Call the target function
    sqlite3_drop_modules(db, azKeep);

    // Close the database connection
    sqlite3_close(db);
}

static void fuzz_sqlite3_realloc(const uint8_t *Data, size_t Size) {
    // Allocate initial memory block
    void *pOld = sqlite3_malloc(100);
    if (!pOld) return;

    // Call the target function with new size
    void *pNew = sqlite3_realloc(pOld, (int)Size);

    // Free the memory if realloc was successful
    if (pNew) sqlite3_free(pNew);
}

static void fuzz_sqlite3_malloc(const uint8_t *Data, size_t Size) {
    // Allocate memory using the size from the input data
    void *pMem = sqlite3_malloc((int)Size);

    // Free the allocated memory
    if (pMem) sqlite3_free(pMem);
}

int LLVMFuzzerTestOneInput_76(const uint8_t *Data, size_t Size) {
    fuzz_sqlite3_complete16(Data, Size);
    fuzz_sqlite3_complete(Data, Size);
    fuzz_sqlite3_drop_modules(Data, Size);
    fuzz_sqlite3_realloc(Data, Size);
    fuzz_sqlite3_malloc(Data, Size);
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

        LLVMFuzzerTestOneInput_76(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    