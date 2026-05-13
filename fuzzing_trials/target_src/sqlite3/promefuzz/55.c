// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_open at sqlite3.c:174695:16 in sqlite3.h
// sqlite3_exec at sqlite3.c:126811:16 in sqlite3.h
// sqlite3_prepare_v2 at sqlite3.c:132572:16 in sqlite3.h
// sqlite3_step at sqlite3.c:79246:16 in sqlite3.h
// sqlite3_column_count at sqlite3.c:79599:16 in sqlite3.h
// sqlite3_column_name16 at sqlite3.c:79887:24 in sqlite3.h
// sqlite3_data_count at sqlite3.c:79609:16 in sqlite3.h
// sqlite3_column_text16 at sqlite3.c:79764:24 in sqlite3.h
// sqlite3_column_int at sqlite3.c:79739:16 in sqlite3.h
// sqlite3_column_decltype16 at sqlite3.c:79910:24 in sqlite3.h
// sqlite3_column_bytes16 at sqlite3.c:79729:16 in sqlite3.h
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

static sqlite3 *initialize_database() {
    sqlite3 *db;
    sqlite3_open(":memory:", &db);
    char *errMsg = 0;
    const char *sql = "CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT);"
                      "INSERT INTO test (name) VALUES ('Alice'), ('Bob'), ('Charlie');";
    sqlite3_exec(db, sql, 0, 0, &errMsg);
    return db;
}

static sqlite3_stmt *prepare_statement(sqlite3 *db) {
    sqlite3_stmt *stmt;
    const char *sql = "SELECT * FROM test;";
    sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    return stmt;
}

int LLVMFuzzerTestOneInput_55(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    sqlite3 *db = initialize_database();
    sqlite3_stmt *stmt = prepare_statement(db);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int column_index = Data[0] % sqlite3_column_count(stmt);

        // Fuzzing sqlite3_column_name16
        const void *name16 = sqlite3_column_name16(stmt, column_index);

        // Fuzzing sqlite3_data_count
        int data_count = sqlite3_data_count(stmt);

        // Fuzzing sqlite3_column_text16
        const void *text16 = sqlite3_column_text16(stmt, column_index);

        // Fuzzing sqlite3_column_int
        int int_value = sqlite3_column_int(stmt, column_index);

        // Fuzzing sqlite3_column_decltype16
        const void *decltype16 = sqlite3_column_decltype16(stmt, column_index);

        // Fuzzing sqlite3_column_bytes16
        int bytes16 = sqlite3_column_bytes16(stmt, column_index);
    }

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

        LLVMFuzzerTestOneInput_55(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    