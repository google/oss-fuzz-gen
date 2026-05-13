#include <stdint.h>
#include <sqlite3.h>
#include <string.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_250(const uint8_t *data, size_t size) {
    // Initialize SQLite database and statement
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int rc;
    
    // Open an in-memory SQLite database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Prepare a SQL statement using the provided data as the SQL query
    // Ensure the data is null-terminated before using it as a string
    char *sql = (char *)malloc(size + 1);
    if (sql == NULL) {
        sqlite3_close(db);
        return 0;
    }
    memcpy(sql, data, size);
    sql[size] = '\0';

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    free(sql);
    if (rc == SQLITE_OK) {
        // Call the function-under-test
        const char *sql_text = sqlite3_sql(stmt);

        // Optionally, use the sql_text for further testing or logging
        if (sql_text != NULL) {
            // For example, just print it (in real fuzzing, this might be omitted)
            // printf("SQL: %s\n", sql_text);
        }

        // Finalize the statement
        sqlite3_finalize(stmt);
    }

    // Close the SQLite database
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

    LLVMFuzzerTestOneInput_250(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
