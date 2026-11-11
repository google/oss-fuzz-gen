#include <stdint.h>
#include <sqlite3.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_249(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated to be used as a SQL query
    char *sql = (char *)malloc(size + 1);
    if (sql == NULL) {
        return 0;
    }
    memcpy(sql, data, size);
    sql[size] = '\0';

    sqlite3 *db;
    sqlite3_stmt *stmt;
    const char *tail;
    int rc;

    // Open an in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        free(sql);
        return 0;
    }

    // Prepare the SQL statement
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, &tail);
    if (rc == SQLITE_OK) {
        // Call the function-under-test
        const char *sql_text = sqlite3_sql(stmt);

        // Optional: Print the SQL text for debugging
        if (sql_text != NULL) {
            printf("SQL Text: %s\n", sql_text);
        }

        // Finalize the statement
        sqlite3_finalize(stmt);
    }

    // Close the database
    sqlite3_close(db);

    // Free the allocated memory
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_249(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
