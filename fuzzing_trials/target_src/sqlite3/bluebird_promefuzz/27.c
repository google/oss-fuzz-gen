#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sqlite3.h"

static int dummy_callback(void *NotUsed, int argc, char **argv, char **azColName) {
    return 0;
}

static int auth_callback(void *pUserData, int actionCode, const char *param1, const char *param2, const char *param3, const char *param4) {
    return SQLITE_OK;
}

int LLVMFuzzerTestOneInput_27(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Create a new in-memory database connection
    sqlite3 *db;
    if (sqlite3_open(":memory:", &db)) {
        return 0;
    }

    // Fuzz sqlite3_set_authorizer
    sqlite3_set_authorizer(db, auth_callback, NULL);

    // Fuzz sqlite3_limit
    sqlite3_limit(db, SQLITE_LIMIT_LENGTH, (int)Data[0]);

    // Prepare a SQL statement from the fuzzed data
    char *sql = (char *)malloc(Size + 1);
    if (sql == NULL) {
        sqlite3_close(db);
        return 0;
    }
    memcpy(sql, Data, Size);
    sql[Size] = '\0';

    // Fuzz sqlite3_exec
    char *errMsg = NULL;
    sqlite3_exec(db, sql, dummy_callback, NULL, &errMsg);
    if (errMsg) {
        sqlite3_free(errMsg);
    }

    // Fuzz sqlite3_enable_load_extension
    sqlite3_enable_load_extension(db, Data[0] % 2);

    // Fuzz sqlite3_create_function
    sqlite3_create_function(db, "dummy_func", 0, SQLITE_UTF8, NULL, NULL, NULL, NULL);

    // Fuzz sqlite3_db_config
    sqlite3_db_config(db, SQLITE_DBCONFIG_LOOKASIDE, NULL, 0, 0);

    // Clean up
    free(sql);
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

    LLVMFuzzerTestOneInput_27(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
