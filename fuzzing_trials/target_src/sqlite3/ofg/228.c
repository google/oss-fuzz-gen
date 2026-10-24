#include <stdint.h>
#include <sqlite3.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_228(const uint8_t *data, size_t size) {
    sqlite3 *db;
    char *errMsg = 0;
    int rc;

    // Ensure the data size is sufficient for a meaningful database name
    if (size < 5) {
        return 0;
    }

    // Create a temporary file for the SQLite database
    char db_filename[] = "/tmp/fuzzdbXXXXXX";
    int fd = mkstemp(db_filename);
    if (fd == -1) {
        return 0;
    }
    close(fd);

    // Open the SQLite database
    rc = sqlite3_open(db_filename, &db);
    if (rc) {
        sqlite3_close(db);
        unlink(db_filename);
        return 0;
    }

    // Create a table to ensure the database is in a usable state
    const char *create_table_sql = "CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, value TEXT);";
    rc = sqlite3_exec(db, create_table_sql, 0, 0, &errMsg);
    if (rc != SQLITE_OK) {
        sqlite3_free(errMsg);
        sqlite3_close(db);
        unlink(db_filename);
        return 0;
    }

    // Use part of the data as the schema name
    char schema_name[size + 1];
    memcpy(schema_name, data, size);
    schema_name[size] = '\0';

    // Call the function-under-test
    sqlite3_wal_checkpoint(db, schema_name);

    // Clean up
    sqlite3_close(db);
    unlink(db_filename);

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

    LLVMFuzzerTestOneInput_228(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
