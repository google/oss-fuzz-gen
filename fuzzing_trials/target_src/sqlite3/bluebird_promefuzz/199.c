#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sqlite3.h"
#include <stdint.h>
#include <string.h>

static void dummy_destructor(void *ptr) {
    // Dummy destructor for sqlite3_bind_text
}

int LLVMFuzzerTestOneInput_199(const uint8_t *Data, size_t Size) {
    if (Size < 100) return 0; // Ensure there's enough data for the test

    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;

    // Open a database connection
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Prepare a dummy SQL statement
    const char *sql = "SELECT * FROM dummy WHERE a = ? AND b = ? AND c = ? AND d = ? AND e = ? AND f = ? AND g = ? AND h = ? AND i = ? AND j = ? AND k = ? AND l = ? AND m = ? AND n = ? AND o = ? AND p = ? AND q = ? AND r = ? AND s = ? AND t = ? AND u = ? AND v = ? AND w = ? AND x = ? AND y = ? AND z = ? AND aa = ? AND ab = ? AND ac = ? AND ad = ? AND ae = ? AND af = ? AND ag = ?";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Bind values to the statement
    int offset = 0;
    rc = sqlite3_bind_int64(stmt, 1, *(sqlite_int64 *)(Data + offset));
    offset += sizeof(sqlite_int64);
    rc = sqlite3_bind_int(stmt, 2, *(int *)(Data + offset));
    offset += sizeof(int);
    rc = sqlite3_bind_text(stmt, 3, (const char *)(Data + offset), 10, dummy_destructor);
    offset += 10;
    rc = sqlite3_bind_int(stmt, 4, *(int *)(Data + offset));
    offset += sizeof(int);
    rc = sqlite3_bind_int64(stmt, 5, *(sqlite_int64 *)(Data + offset));
    offset += sizeof(sqlite_int64);
    rc = sqlite3_bind_text(stmt, 6, (const char *)(Data + offset), 10, dummy_destructor);
    offset += 10;
    rc = sqlite3_bind_int(stmt, 7, *(int *)(Data + offset));
    offset += sizeof(int);
    rc = sqlite3_bind_int64(stmt, 8, *(sqlite_int64 *)(Data + offset));
    offset += sizeof(sqlite_int64);
    rc = sqlite3_bind_text(stmt, 9, (const char *)(Data + offset), 10, dummy_destructor);
    offset += 10;
    rc = sqlite3_bind_int(stmt, 10, *(int *)(Data + offset));
    offset += sizeof(int);
    rc = sqlite3_bind_int(stmt, 11, *(int *)(Data + offset));
    offset += sizeof(int);
    rc = sqlite3_bind_text(stmt, 12, (const char *)(Data + offset), 10, dummy_destructor);
    offset += 10;
    rc = sqlite3_bind_text(stmt, 13, (const char *)(Data + offset), 10, dummy_destructor);
    offset += 10;
    rc = sqlite3_bind_text(stmt, 14, (const char *)(Data + offset), 10, dummy_destructor);
    offset += 10;
    rc = sqlite3_bind_int(stmt, 15, *(int *)(Data + offset));
    offset += sizeof(int);
    rc = sqlite3_bind_int(stmt, 16, *(int *)(Data + offset));
    offset += sizeof(int);
    rc = sqlite3_bind_int(stmt, 17, *(int *)(Data + offset));
    offset += sizeof(int);
    rc = sqlite3_bind_int(stmt, 18, *(int *)(Data + offset));
    offset += sizeof(int);
    rc = sqlite3_bind_text(stmt, 19, (const char *)(Data + offset), 10, dummy_destructor);
    offset += 10;
    rc = sqlite3_bind_int(stmt, 20, *(int *)(Data + offset));
    offset += sizeof(int);
    rc = sqlite3_bind_int(stmt, 21, *(int *)(Data + offset));
    offset += sizeof(int);
    rc = sqlite3_bind_int(stmt, 22, *(int *)(Data + offset));
    offset += sizeof(int);
    rc = sqlite3_bind_int(stmt, 23, *(int *)(Data + offset));
    offset += sizeof(int);
    rc = sqlite3_bind_int(stmt, 24, *(int *)(Data + offset));
    offset += sizeof(int);
    rc = sqlite3_bind_int(stmt, 25, *(int *)(Data + offset));
    offset += sizeof(int);
    rc = sqlite3_bind_int(stmt, 26, *(int *)(Data + offset));
    offset += sizeof(int);
    rc = sqlite3_bind_int(stmt, 27, *(int *)(Data + offset));
    offset += sizeof(int);
    rc = sqlite3_bind_int(stmt, 28, *(int *)(Data + offset));
    offset += sizeof(int);
    rc = sqlite3_bind_int(stmt, 29, *(int *)(Data + offset));
    offset += sizeof(int);
    rc = sqlite3_bind_text(stmt, 30, (const char *)(Data + offset), 10, dummy_destructor);
    offset += 10;
    rc = sqlite3_bind_int(stmt, 31, *(int *)(Data + offset));
    offset += sizeof(int);
    int version = sqlite3_libversion_number();
    (void)version; // Suppress unused variable warning
    rc = sqlite3_bind_int(stmt, 32, *(int *)(Data + offset));
    offset += sizeof(int);
    rc = sqlite3_bind_text(stmt, 33, (const char *)(Data + offset), 10, dummy_destructor);
    offset += 10;
    rc = sqlite3_bind_text(stmt, 34, (const char *)(Data + offset), 10, dummy_destructor);

    // Finalize the statement
    sqlite3_finalize(stmt);

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

    LLVMFuzzerTestOneInput_199(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
