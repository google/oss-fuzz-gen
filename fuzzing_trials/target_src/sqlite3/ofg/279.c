#include <stdint.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_279(const uint8_t *data, size_t size) {
    sqlite3 *db;
    int rc;
    char *errMsg = 0;

    // Open a new in-memory SQLite database
    rc = sqlite3_open(":memory:", &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return 0;
    }

    // Execute a SQL statement using the fuzz data
    if (size > 0) {
        char *sql = (char *)malloc(size + 1);
        if (sql == NULL) {
            sqlite3_close(db);
            return 0;
        }

        memcpy(sql, data, size);
        sql[size] = '\0'; // Null-terminate the SQL statement

        rc = sqlite3_exec(db, sql, 0, 0, &errMsg);
        if (rc != SQLITE_OK) {
            // Call the function-under-test
            const char *errorMessage = sqlite3_errmsg(db);
            if (errorMessage != NULL) {
                // Print the error message for debugging purposes
                fprintf(stderr, "SQL error: %s\n", errorMessage);
            }
            sqlite3_free(errMsg);
        }

        free(sql);
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

    LLVMFuzzerTestOneInput_279(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
