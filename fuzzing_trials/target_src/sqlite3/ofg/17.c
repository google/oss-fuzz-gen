#include <stdint.h>
#include <sqlite3.h>
#include <string.h>
#include <stdlib.h> // Include for malloc and free

int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0; // Not enough data to create a valid SQL statement
    }

    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    const void *tail = NULL;

    // Open an in-memory database
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        return 0; // Failed to open database
    }

    // Ensure the data is null-terminated for sqlite3_prepare16
    void *sql = malloc(size + 2);
    if (sql == NULL) {
        sqlite3_close(db);
        return 0; // Memory allocation failed
    }
    memcpy(sql, data, size);
    ((char *)sql)[size] = '\0';
    ((char *)sql)[size + 1] = '\0'; // Ensure double null-termination for UTF-16

    // Call the function-under-test
    sqlite3_prepare16(db, sql, size, &stmt, &tail);

    // Clean up
    if (stmt != NULL) {
        sqlite3_finalize(stmt);
    }
    free(sql);
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

    LLVMFuzzerTestOneInput_17(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
