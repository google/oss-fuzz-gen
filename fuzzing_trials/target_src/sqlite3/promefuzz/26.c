// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_errmsg at sqlite3.c:173721:24 in sqlite3.h
// sqlite3_step at sqlite3.c:79246:16 in sqlite3.h
// sqlite3_errmsg at sqlite3.c:173721:24 in sqlite3.h
// sqlite3_errmsg at sqlite3.c:173721:24 in sqlite3.h
// sqlite3_reset at sqlite3.c:78461:16 in sqlite3.h
// sqlite3_errmsg at sqlite3.c:173721:24 in sqlite3.h
// sqlite3_errmsg at sqlite3.c:173721:24 in sqlite3.h
// sqlite3_bind_text at sqlite3.c:80158:16 in sqlite3.h
// sqlite3_errmsg at sqlite3.c:173721:24 in sqlite3.h
// sqlite3_prepare_v2 at sqlite3.c:132572:16 in sqlite3.h
// sqlite3_step at sqlite3.c:79246:16 in sqlite3.h
// sqlite3_errmsg at sqlite3.c:173721:24 in sqlite3.h
// sqlite3_column_int64 at sqlite3.c:79744:25 in sqlite3.h
// sqlite3_errmsg at sqlite3.c:173721:24 in sqlite3.h
// sqlite3_finalize at sqlite3.c:78432:16 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
// sqlite3_open at sqlite3.c:174695:16 in sqlite3.h
// sqlite3_errmsg at sqlite3.c:173721:24 in sqlite3.h
// sqlite3_bind_text at sqlite3.c:80158:16 in sqlite3.h
// sqlite3_errmsg at sqlite3.c:173721:24 in sqlite3.h
// sqlite3_step at sqlite3.c:79246:16 in sqlite3.h
// sqlite3_errmsg at sqlite3.c:173721:24 in sqlite3.h
// sqlite3_reset at sqlite3.c:78461:16 in sqlite3.h
// sqlite3_errmsg at sqlite3.c:173721:24 in sqlite3.h
// sqlite3_bind_text at sqlite3.c:80158:16 in sqlite3.h
// sqlite3_errmsg at sqlite3.c:173721:24 in sqlite3.h
// sqlite3_step at sqlite3.c:79246:16 in sqlite3.h
// sqlite3_errmsg at sqlite3.c:173721:24 in sqlite3.h
// sqlite3_errmsg at sqlite3.c:173721:24 in sqlite3.h
// sqlite3_reset at sqlite3.c:78461:16 in sqlite3.h
// sqlite3_errmsg at sqlite3.c:173721:24 in sqlite3.h
// sqlite3_bind_text at sqlite3.c:80158:16 in sqlite3.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

static int execute_sql(sqlite3 *db, const char *sql, sqlite3_stmt **stmt) {
    int rc = sqlite3_prepare_v2(db, sql, -1, stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return rc;
    }
    return SQLITE_OK;
}

static void cleanup(sqlite3 *db, sqlite3_stmt *stmt) {
    if (stmt) {
        sqlite3_finalize(stmt);
    }
    if (db) {
        sqlite3_close(db);
    }
}

int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int rc;
    const char *sql = "CREATE TABLE IF NOT EXISTS test(id INTEGER PRIMARY KEY, value TEXT);"
                      "INSERT INTO test(value) VALUES('Hello'), ('World');"
                      "SELECT * FROM test WHERE id = ?;";

    // Open a connection to an in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return 0;
    }

    // Execute the SQL statements
    rc = execute_sql(db, sql, &stmt);
    if (rc != SQLITE_OK) {
        cleanup(db, stmt);
        return 0;
    }

    // Bind text using fuzz data
    rc = sqlite3_bind_text(stmt, 1, (const char *)Data, Size, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to bind text: %s\n", sqlite3_errmsg(db));
        cleanup(db, stmt);
        return 0;
    }

    // Step through the results
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to step: %s\n", sqlite3_errmsg(db));
    }

    // Reset the statement
    rc = sqlite3_reset(stmt);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to reset: %s\n", sqlite3_errmsg(db));
    }

    // Re-bind text using fuzz data
    rc = sqlite3_bind_text(stmt, 1, (const char *)Data, Size, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to re-bind text: %s\n", sqlite3_errmsg(db));
        cleanup(db, stmt);
        return 0;
    }

    // Step through the results again
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to step again: %s\n", sqlite3_errmsg(db));
    }

    // Get error message
    const char *errmsg = sqlite3_errmsg(db);
    fprintf(stderr, "Error message: %s\n", errmsg);

    // Reset the statement again
    rc = sqlite3_reset(stmt);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to reset again: %s\n", sqlite3_errmsg(db));
    }

    // Bind text using fuzz data again
    rc = sqlite3_bind_text(stmt, 1, (const char *)Data, Size, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to bind text again: %s\n", sqlite3_errmsg(db));
        cleanup(db, stmt);
        return 0;
    }

    // Step through the results again
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to step again: %s\n", sqlite3_errmsg(db));
    }

    // Get error message again
    errmsg = sqlite3_errmsg(db);
    fprintf(stderr, "Error message again: %s\n", errmsg);

    // Reset the statement again
    rc = sqlite3_reset(stmt);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to reset again: %s\n", sqlite3_errmsg(db));
    }

    // Get error message again
    errmsg = sqlite3_errmsg(db);
    fprintf(stderr, "Error message again: %s\n", errmsg);

    // Bind text using fuzz data again
    rc = sqlite3_bind_text(stmt, 1, (const char *)Data, Size, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to bind text again: %s\n", sqlite3_errmsg(db));
        cleanup(db, stmt);
        return 0;
    }

    // Step through the results again
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to step again: %s\n", sqlite3_errmsg(db));
    }

    // Retrieve a 64-bit integer from the first column
    if (rc == SQLITE_ROW) {
        sqlite3_int64 value = sqlite3_column_int64(stmt, 0);
        fprintf(stderr, "Retrieved int64: %lld\n", value);
    }

    cleanup(db, stmt);
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

        if(size < 1 + 1)
            exit(0);

        data = (uint8_t *)malloc((size_t)size);
        if(data == NULL)
            exit(0);

        if(fread(data, (size_t)size, 1, f) != 1)
            exit(0);

        LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    