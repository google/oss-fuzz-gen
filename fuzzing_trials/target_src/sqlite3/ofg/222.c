#include <stdint.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

// Fuzzing function
int LLVMFuzzerTestOneInput_222(const uint8_t *data, size_t size) {
    sqlite3 *db;
    int rc;
    char *errMsg = 0;
    char *sql = NULL;

    // Open a new in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return 0;
    }

    // Allocate memory for SQL statement
    sql = (char *)malloc(size + 1);
    if (sql == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        sqlite3_close(db);
        return 0;
    }

    // Copy input data to SQL statement
    memcpy(sql, data, size);
    sql[size] = '\0'; // Null-terminate the string

    // Execute the SQL statement
    rc = sqlite3_exec(db, sql, 0, 0, &errMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", errMsg);
        sqlite3_free(errMsg);
    }

    // Call the function-under-test
    sqlite3_interrupt(db);

    // Free allocated memory
    free(sql);

    // Close the database connection
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

    LLVMFuzzerTestOneInput_222(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
