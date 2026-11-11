// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_bind_int at sqlite3.c:80115:16 in sqlite3.h
// sqlite3_bind_text at sqlite3.c:80158:16 in sqlite3.h
// sqlite3_bind_text at sqlite3.c:80158:16 in sqlite3.h
// sqlite3_finalize at sqlite3.c:78432:16 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
// sqlite3_open at sqlite3.c:174695:16 in sqlite3.h
// sqlite3_prepare_v2 at sqlite3.c:132572:16 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
// sqlite3_bind_int64 at sqlite3.c:80118:16 in sqlite3.h
// sqlite3_bind_int at sqlite3.c:80115:16 in sqlite3.h
// sqlite3_bind_text at sqlite3.c:80158:16 in sqlite3.h
// sqlite3_bind_int at sqlite3.c:80115:16 in sqlite3.h
// sqlite3_bind_int64 at sqlite3.c:80118:16 in sqlite3.h
// sqlite3_bind_text at sqlite3.c:80158:16 in sqlite3.h
// sqlite3_bind_int at sqlite3.c:80115:16 in sqlite3.h
// sqlite3_bind_int64 at sqlite3.c:80118:16 in sqlite3.h
// sqlite3_bind_text at sqlite3.c:80158:16 in sqlite3.h
// sqlite3_bind_int at sqlite3.c:80115:16 in sqlite3.h
// sqlite3_bind_int at sqlite3.c:80115:16 in sqlite3.h
// sqlite3_bind_text at sqlite3.c:80158:16 in sqlite3.h
// sqlite3_bind_text at sqlite3.c:80158:16 in sqlite3.h
// sqlite3_bind_text at sqlite3.c:80158:16 in sqlite3.h
// sqlite3_bind_int at sqlite3.c:80115:16 in sqlite3.h
// sqlite3_bind_int at sqlite3.c:80115:16 in sqlite3.h
// sqlite3_bind_int at sqlite3.c:80115:16 in sqlite3.h
// sqlite3_bind_int at sqlite3.c:80115:16 in sqlite3.h
// sqlite3_bind_text at sqlite3.c:80158:16 in sqlite3.h
// sqlite3_bind_int at sqlite3.c:80115:16 in sqlite3.h
// sqlite3_bind_int at sqlite3.c:80115:16 in sqlite3.h
// sqlite3_bind_int at sqlite3.c:80115:16 in sqlite3.h
// sqlite3_bind_int at sqlite3.c:80115:16 in sqlite3.h
// sqlite3_bind_int at sqlite3.c:80115:16 in sqlite3.h
// sqlite3_bind_int at sqlite3.c:80115:16 in sqlite3.h
// sqlite3_bind_int at sqlite3.c:80115:16 in sqlite3.h
// sqlite3_bind_int at sqlite3.c:80115:16 in sqlite3.h
// sqlite3_bind_int at sqlite3.c:80115:16 in sqlite3.h
// sqlite3_bind_int at sqlite3.c:80115:16 in sqlite3.h
// sqlite3_bind_text at sqlite3.c:80158:16 in sqlite3.h
// sqlite3_bind_int at sqlite3.c:80115:16 in sqlite3.h
// sqlite3_libversion_number at sqlite3.c:171129:16 in sqlite3.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sqlite3.h>
#include <stdint.h>
#include <string.h>

static void dummy_destructor(void *ptr) {
    // Dummy destructor for sqlite3_bind_text
}

int LLVMFuzzerTestOneInput_21(const uint8_t *Data, size_t Size) {
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

        if(size < 1 + 1)
            exit(0);

        data = (uint8_t *)malloc((size_t)size);
        if(data == NULL)
            exit(0);

        if(fread(data, (size_t)size, 1, f) != 1)
            exit(0);

        LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    