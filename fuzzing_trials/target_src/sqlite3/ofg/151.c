#include <sqlite3.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

int LLVMFuzzerTestOneInput_151(const uint8_t *data, size_t size) {
    sqlite3 *db;
    const char *db_name = ":memory:"; // Use an in-memory database
    const char *zDbName = "main";    // Default schema name
    const char *zTableName = "test"; // Example table name
    const char *zColumnName = "col"; // Example column name
    const char **pzDataType = NULL;
    const char **pzCollSeq = NULL;
    int notNull = 0;
    int primaryKey = 0;
    int autoInc = 0;

    // Open an in-memory database
    if (sqlite3_open(db_name, &db) != SQLITE_OK) {
        return 0;
    }

    // Create a simple table for testing
    const char *createTableSQL = "CREATE TABLE test (col INTEGER);";
    sqlite3_exec(db, createTableSQL, 0, 0, 0);

    // Call the function-under-test
    sqlite3_table_column_metadata(db, zDbName, zTableName, zColumnName, pzDataType, pzCollSeq, &notNull, &primaryKey, &autoInc);

    // Clean up
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

    LLVMFuzzerTestOneInput_151(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
