#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sqlite3.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

static void prepare_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fputs("CREATE TABLE test(id INT, name TEXT);", file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_169(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) {
        return 0;
    }

    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;
    const char *sql = "INSERT INTO test(id, name) VALUES(?, ?);";

    prepare_dummy_file();

    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    rc = sqlite3_exec(db, "CREATE TABLE test(id INT, name TEXT);", 0, 0, 0);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    int param_count = sqlite3_bind_parameter_count(stmt);
    if (param_count > 0) {
        const char *param_name = sqlite3_bind_parameter_name(stmt, 1);
        if (param_name != NULL) {
            sqlite3_bind_int(stmt, 1, (int)Data[0]);
        }
    }

    sqlite3_uint64 alloc_size = (sqlite3_uint64)Size;
    void *memory = sqlite3_malloc64(alloc_size);
    if (memory) {
        memcpy(memory, Data, Size);
        sqlite3_bind_text64(stmt, 2, (const char *)memory, alloc_size, sqlite3_free, SQLITE_UTF8);
    }

    sqlite3_step(stmt);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_169(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
