// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_prepare at sqlite3.c:132560:16 in sqlite3.h
// sqlite3_stmt_readonly at sqlite3.c:80356:16 in sqlite3.h
// sqlite3_stmt_busy at sqlite3.c:80407:16 in sqlite3.h
// sqlite3_expired at sqlite3.c:78362:16 in sqlite3.h
// sqlite3_transfer_bindings at sqlite3.c:80324:16 in sqlite3.h
// sqlite3_stmt_explain at sqlite3.c:80371:16 in sqlite3.h
// sqlite3_open at sqlite3.c:174695:16 in sqlite3.h
// sqlite3_finalize at sqlite3.c:78432:16 in sqlite3.h
// sqlite3_finalize at sqlite3.c:78432:16 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static int prepare_statement(sqlite3 *db, const char *sql, sqlite3_stmt **stmt, const char **tail) {
    return sqlite3_prepare(db, sql, -1, stmt, tail);
}

static void test_sqlite3_stmt_readonly(sqlite3_stmt *stmt) {
    if (stmt) {
        int readonly = sqlite3_stmt_readonly(stmt);
        (void)readonly; // Suppress unused variable warning
    }
}

static void test_sqlite3_stmt_busy(sqlite3_stmt *stmt) {
    if (stmt) {
        int busy = sqlite3_stmt_busy(stmt);
        (void)busy; // Suppress unused variable warning
    }
}

static void test_sqlite3_expired(sqlite3_stmt *stmt) {
    if (stmt) {
        int expired = sqlite3_expired(stmt);
        (void)expired; // Suppress unused variable warning
    }
}

static void test_sqlite3_transfer_bindings(sqlite3_stmt *stmt1, sqlite3_stmt *stmt2) {
    if (stmt1 && stmt2) {
        int result = sqlite3_transfer_bindings(stmt1, stmt2);
        (void)result; // Suppress unused variable warning
    }
}

static void test_sqlite3_stmt_explain(sqlite3_stmt *stmt, int mode) {
    if (stmt) {
        int result = sqlite3_stmt_explain(stmt, mode);
        (void)result; // Suppress unused variable warning
    }
}

int LLVMFuzzerTestOneInput_87(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
    const char *tail = NULL;
    char *sql = (char *)malloc(Size + 1);
    if (!sql) return 0;
    memcpy(sql, Data, Size);
    sql[Size] = '\0';

    if (sqlite3_open("./dummy_file", &db) != SQLITE_OK) {
        free(sql);
        return 0;
    }

    if (prepare_statement(db, sql, &stmt, &tail) == SQLITE_OK) {
        test_sqlite3_stmt_readonly(stmt);
        test_sqlite3_stmt_busy(stmt);
        test_sqlite3_expired(stmt);

        // Create another statement to test sqlite3_transfer_bindings
        sqlite3_stmt *stmt2 = NULL;
        if (prepare_statement(db, sql, &stmt2, &tail) == SQLITE_OK) {
            test_sqlite3_transfer_bindings(stmt, stmt2);
            sqlite3_finalize(stmt2);
        }

        // Test different explain modes
        for (int mode = 0; mode <= 2; ++mode) {
            test_sqlite3_stmt_explain(stmt, mode);
        }

        sqlite3_finalize(stmt);
    }

    sqlite3_close(db);
    free(sql);
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

        LLVMFuzzerTestOneInput_87(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    