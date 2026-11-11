#include <sys/stat.h>
#include <stdint.h>
#include "sqlite3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // Include this for mkstemp() and unlink()
#include <inttypes.h> // Include this for PRId64

int LLVMFuzzerTestOneInput_173(const uint8_t *data, size_t size) {
    sqlite3 *db;
    char *errMsg = 0;
    int rc;
    sqlite3_int64 lastRowId;

    // Ensure that the data is not empty and has a reasonable size
    if (size == 0 || size > 1024) {
        return 0;
    }

    // Create a temporary filename for the SQLite database
    char dbName[] = "/tmp/fuzzdbXXXXXX";
    int fd = mkstemp(dbName);
    if (fd == -1) {
        return 0;
    }
    close(fd);

    // Open the SQLite database
    rc = sqlite3_open(dbName, &db);
    if (rc) {
        sqlite3_close(db);
        return 0;
    }

    // Create a table
    const char *createTableSQL = "CREATE TABLE IF NOT EXISTS fuzz_table (id INTEGER PRIMARY KEY, data BLOB);";
    rc = sqlite3_exec(db, createTableSQL, 0, 0, &errMsg);
    if (rc != SQLITE_OK) {
        sqlite3_free(errMsg);
        sqlite3_close(db);
        return 0;
    }

    // Prepare an INSERT statement
    sqlite3_stmt *stmt;
    const char *insertSQL = "INSERT INTO fuzz_table (data) VALUES (?);";
    rc = sqlite3_prepare_v2(db, insertSQL, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Bind the input data to the INSERT statement
    rc = sqlite3_bind_blob(stmt, 1, data, size, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }

    // Execute the INSERT statement
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }

    // Finalize the statement
    sqlite3_finalize(stmt);

    // Call the function-under-test
    lastRowId = sqlite3_last_insert_rowid(db);

    // Output the result (for debugging purposes)
    printf("Last Insert Row ID: %" PRId64 "\n", lastRowId);

    // Close the database
    sqlite3_close(db);

    // Remove the temporary database file
    unlink(dbName);

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

    LLVMFuzzerTestOneInput_173(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
