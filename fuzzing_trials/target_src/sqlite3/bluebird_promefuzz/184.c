#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sqlite3.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

static void prepare_dummy_db(sqlite3 **db, sqlite3_stmt **stmt) {
    sqlite3_open(":memory:", db);
    const char *sql = "CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT);"
                      "INSERT INTO test (value) VALUES ('value1');"
                      "INSERT INTO test (value) VALUES ('value2');"
                      "SELECT * FROM test;";
    sqlite3_prepare_v2(*db, sql, -1, stmt, NULL);
}

static void cleanup(sqlite3 *db, sqlite3_stmt *stmt) {
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

int LLVMFuzzerTestOneInput_184(const uint8_t *Data, size_t Size) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    prepare_dummy_db(&db, &stmt);

    int column_count = sqlite3_column_count(stmt);
    int stmt_status = sqlite3_stmt_status(stmt, SQLITE_STMTSTATUS_FULLSCAN_STEP, 0);
    int is_busy = sqlite3_stmt_busy(stmt);
    int transfer_bindings_result = sqlite3_transfer_bindings(stmt, stmt); // Just transferring to itself for testing
    const char *param_name = sqlite3_bind_parameter_name(stmt, 1);
    int clear_bindings_result = sqlite3_clear_bindings(stmt);

    if (column_count > 0) {
        for (int i = 0; i < column_count; i++) {
            sqlite3_step(stmt);
        }
    }

    cleanup(db, stmt);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_184(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
