// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_error_offset at sqlite3.c:173770:16 in sqlite3.h
// sqlite3_column_count at sqlite3.c:79599:16 in sqlite3.h
// sqlite3_column_type at sqlite3.c:79770:16 in sqlite3.h
// sqlite3_keyword_count at sqlite3.c:169871:16 in sqlite3.h
// sqlite3_keyword_count at sqlite3.c:169871:16 in sqlite3.h
// sqlite3_keyword_name at sqlite3.c:169864:16 in sqlite3.h
// sqlite3_column_count at sqlite3.c:79599:16 in sqlite3.h
// sqlite3_column_blob at sqlite3.c:79714:24 in sqlite3.h
// sqlite3_keyword_check at sqlite3.c:169872:16 in sqlite3.h
// sqlite3_open at sqlite3.c:174695:16 in sqlite3.h
// sqlite3_exec at sqlite3.c:126811:16 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
// sqlite3_prepare_v2 at sqlite3.c:132572:16 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
// sqlite3_finalize at sqlite3.c:78432:16 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdint.h>
#include <sqlite3.h>

static void test_sqlite3_error_offset(sqlite3 *db) {
    int offset = sqlite3_error_offset(db);
    (void)offset; // Suppress unused variable warning
}

static void test_sqlite3_column_type(sqlite3_stmt *stmt) {
    int columnCount = sqlite3_column_count(stmt);
    for (int i = 0; i < columnCount; i++) {
        int type = sqlite3_column_type(stmt, i);
        (void)type; // Suppress unused variable warning
    }
}

static void test_sqlite3_keyword_count(void) {
    int keywordCount = sqlite3_keyword_count();
    (void)keywordCount; // Suppress unused variable warning
}

static void test_sqlite3_keyword_name(void) {
    int keywordCount = sqlite3_keyword_count();
    for (int i = 0; i < keywordCount; i++) {
        const char *keyword;
        int length;
        if (sqlite3_keyword_name(i, &keyword, &length) == SQLITE_OK) {
            (void)keyword; // Suppress unused variable warning
            (void)length;  // Suppress unused variable warning
        }
    }
}

static void test_sqlite3_column_blob(sqlite3_stmt *stmt) {
    int columnCount = sqlite3_column_count(stmt);
    for (int i = 0; i < columnCount; i++) {
        const void *blob = sqlite3_column_blob(stmt, i);
        (void)blob; // Suppress unused variable warning
    }
}

static void test_sqlite3_keyword_check(void) {
    const char *keywords[] = {"SELECT", "INSERT", "UPDATE", "DELETE", "BEGIN", "END"};
    for (int i = 0; i < sizeof(keywords) / sizeof(keywords[0]); i++) {
        int isKeyword = sqlite3_keyword_check(keywords[i], (int)strlen(keywords[i]));
        (void)isKeyword; // Suppress unused variable warning
    }
}

int LLVMFuzzerTestOneInput_60(const uint8_t *Data, size_t Size) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;

    // Initialize SQLite database in memory
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Create a dummy table
    rc = sqlite3_exec(db, "CREATE TABLE dummy (id INTEGER PRIMARY KEY, data BLOB);", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Prepare a dummy statement
    rc = sqlite3_prepare_v2(db, "SELECT * FROM dummy;", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Fuzz the target functions
    test_sqlite3_error_offset(db);
    test_sqlite3_column_type(stmt);
    test_sqlite3_keyword_count();
    test_sqlite3_keyword_name();
    test_sqlite3_column_blob(stmt);
    test_sqlite3_keyword_check();

    // Clean up
    sqlite3_finalize(stmt);
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

        LLVMFuzzerTestOneInput_60(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    