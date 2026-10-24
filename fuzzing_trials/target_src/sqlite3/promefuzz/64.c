// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_open16 at sqlite3.c:174715:16 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
// sqlite3_prepare16_v3 at sqlite3.c:132712:16 in sqlite3.h
// sqlite3_finalize at sqlite3.c:78432:16 in sqlite3.h
// sqlite3_prepare16 at sqlite3.c:132688:16 in sqlite3.h
// sqlite3_bind_text16 at sqlite3.c:80183:16 in sqlite3.h
// sqlite3_finalize at sqlite3.c:78432:16 in sqlite3.h
// sqlite3_create_collation16 at sqlite3.c:174792:16 in sqlite3.h
// sqlite3_prepare16_v2 at sqlite3.c:132700:16 in sqlite3.h
// sqlite3_finalize at sqlite3.c:78432:16 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int dummy_compare(void *pArg, int len1, const void *str1, int len2, const void *str2) {
    return 0; // Dummy comparison function
}

int LLVMFuzzerTestOneInput_64(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0;

    // Initialize variables
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    const void *tail = NULL;

    // Create a UTF-16 encoded dummy database filename
    char dbname[] = "./dummy_file";
    void *utf16_dbname = malloc(sizeof(dbname) * 2);
    if (!utf16_dbname) return 0;
    for (size_t i = 0; i < sizeof(dbname); ++i) {
        ((char *)utf16_dbname)[i * 2] = dbname[i];
        ((char *)utf16_dbname)[i * 2 + 1] = 0;
    }

    // Open the database
    if (sqlite3_open16(utf16_dbname, &db) != SQLITE_OK) {
        free(utf16_dbname);
        return 0;
    }
    free(utf16_dbname);

    // Prepare a UTF-16 SQL statement
    size_t sqlSize = Size > 100 ? 100 : Size;
    void *utf16_sql = malloc((sqlSize + 1) * 2); // Allocate extra space for null terminator
    if (!utf16_sql) {
        sqlite3_close(db);
        return 0;
    }
    for (size_t i = 0; i < sqlSize; ++i) {
        ((char *)utf16_sql)[i * 2] = Data[i];
        ((char *)utf16_sql)[i * 2 + 1] = 0;
    }
    ((char *)utf16_sql)[sqlSize * 2] = 0; // Null terminator
    ((char *)utf16_sql)[sqlSize * 2 + 1] = 0; // Null terminator

    // Fuzz sqlite3_prepare16_v3
    sqlite3_prepare16_v3(db, utf16_sql, sqlSize * 2, 0, &stmt, &tail);
    if (stmt) sqlite3_finalize(stmt);

    // Fuzz sqlite3_bind_text16
    sqlite3_prepare16(db, utf16_sql, sqlSize * 2, &stmt, &tail);
    if (stmt) {
        sqlite3_bind_text16(stmt, 1, utf16_sql, sqlSize * 2, SQLITE_STATIC);
        sqlite3_finalize(stmt);
    }

    // Fuzz sqlite3_create_collation16
    sqlite3_create_collation16(db, utf16_sql, SQLITE_UTF16, NULL, dummy_compare);

    // Fuzz sqlite3_prepare16_v2
    sqlite3_prepare16_v2(db, utf16_sql, sqlSize * 2, &stmt, &tail);
    if (stmt) sqlite3_finalize(stmt);

    // Cleanup
    free(utf16_sql);
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

        LLVMFuzzerTestOneInput_64(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    