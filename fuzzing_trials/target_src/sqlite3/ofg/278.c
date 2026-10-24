#include <stdint.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_278(const uint8_t *data, size_t size) {
    sqlite3 *db;
    int rc;
    char *errMsg = 0;

    // Initialize SQLite database in memory
    rc = sqlite3_open(":memory:", &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return 0;
    }

    // Create a table
    const char *sql = "CREATE TABLE IF NOT EXISTS test (id INT, value TEXT);";
    rc = sqlite3_exec(db, sql, 0, 0, &errMsg);
    if (rc != SQLITE_OK) {
        sqlite3_free(errMsg);
    }

    // Use the fuzz data to execute a SQL command
    char *fuzzSql = (char *)malloc(size + 1);
    if (fuzzSql == NULL) {
        sqlite3_close(db);
        return 0;
    }
    memcpy(fuzzSql, data, size);
    fuzzSql[size] = '\0';

    rc = sqlite3_exec(db, fuzzSql, 0, 0, &errMsg);
    if (rc != SQLITE_OK) {
        // Call the function-under-test
        const char *errmsg = sqlite3_errmsg(db);
        printf("SQLite Error: %s\n", errmsg);
        sqlite3_free(errMsg);
    }

    free(fuzzSql);
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

    LLVMFuzzerTestOneInput_278(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
