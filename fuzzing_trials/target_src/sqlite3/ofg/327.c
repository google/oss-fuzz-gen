#include <stdint.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

// Define a custom destructor function to match the function signature
void custom_destructor_327(void *ptr) {
    // Free the allocated memory
    free(ptr);
}

int LLVMFuzzerTestOneInput_327(const uint8_t *data, size_t size) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;
    const char *sql_create = "CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT);";
    const char *sql_insert = "INSERT INTO test (id, value) VALUES (?, ?);";

    // Open an in-memory SQLite database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Execute the SQL statement to create the table
    rc = sqlite3_exec(db, sql_create, 0, 0, 0);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Prepare the SQL insert statement
    rc = sqlite3_prepare_v2(db, sql_insert, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Allocate memory for the text data to bind
    char *text_data = (char *)malloc(size + 1);
    if (text_data == NULL) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }

    // Copy the fuzzing data into the allocated memory and null-terminate it
    memcpy(text_data, data, size);
    text_data[size] = '\0';

    // Bind a constant integer to the first parameter
    rc = sqlite3_bind_int(stmt, 1, 1);
    if (rc != SQLITE_OK) {
        free(text_data);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }

    // Bind the text data to the second parameter of the SQL statement
    sqlite3_uint64 text_size = (sqlite3_uint64)size;
    rc = sqlite3_bind_text64(stmt, 2, text_data, text_size, custom_destructor_327, SQLITE_UTF8);
    if (rc != SQLITE_OK) {
        free(text_data);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }

    // Execute the SQL statement
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }

    // Finalize the statement and close the database
    sqlite3_finalize(stmt);
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

    LLVMFuzzerTestOneInput_327(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
