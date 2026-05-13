// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_open at sqlite3.c:174695:16 in sqlite3.h
// sqlite3_exec at sqlite3.c:126811:16 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
// sqlite3_prepare_v2 at sqlite3.c:132572:16 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
// sqlite3_bind_int at sqlite3.c:80115:16 in sqlite3.h
// sqlite3_bind_int64 at sqlite3.c:80118:16 in sqlite3.h
// sqlite3_bind_double at sqlite3.c:80104:16 in sqlite3.h
// sqlite3_bind_text64 at sqlite3.c:80167:16 in sqlite3.h
// sqlite3_bind_int at sqlite3.c:80115:16 in sqlite3.h
// sqlite3_finalize at sqlite3.c:78432:16 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sqlite3.h>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_31(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int) + sizeof(sqlite3_int64) + sizeof(double) + sizeof(sqlite3_uint64) + 1) {
        return 0;
    }

    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;

    // Open a new database connection
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Create a dummy table
    const char *createTableSQL = "CREATE TABLE IF NOT EXISTS test (a INTEGER, b INTEGER, c REAL, d TEXT)";
    rc = sqlite3_exec(db, createTableSQL, 0, 0, 0);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Prepare a dummy statement
    const char *sql = "INSERT INTO test (a, b, c, d) VALUES (?, ?, ?, ?)";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Extract values from Data
    int intValue1 = *(int *)Data;
    Data += sizeof(int);

    sqlite3_int64 int64Value = *(sqlite3_int64 *)Data;
    Data += sizeof(sqlite3_int64);

    double doubleValue = *(double *)Data;
    Data += sizeof(double);

    sqlite3_uint64 textSize = *(sqlite3_uint64 *)Data;
    Data += sizeof(sqlite3_uint64);

    unsigned char encoding = *Data;
    Data += 1;

    // Ensure textSize does not exceed remaining data
    if (textSize > Size - (Data - (const uint8_t *)Data)) {
        textSize = Size - (Data - (const uint8_t *)Data);
    }

    // Bind values to the statement
    sqlite3_bind_int(stmt, 1, intValue1);
    sqlite3_bind_int64(stmt, 2, int64Value);
    sqlite3_bind_double(stmt, 3, doubleValue);

    // Use SQLITE_TRANSIENT to safely copy the data
    rc = sqlite3_bind_text64(stmt, 4, (const char *)Data, textSize, SQLITE_TRANSIENT, encoding);
    if (rc != SQLITE_OK) {
        // Handle error if necessary
    }
    sqlite3_bind_int(stmt, 1, intValue1);  // Re-bind to explore more states

    // Cleanup
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

        if(size < 1 + 1)
            exit(0);

        data = (uint8_t *)malloc((size_t)size);
        if(data == NULL)
            exit(0);

        if(fread(data, (size_t)size, 1, f) != 1)
            exit(0);

        LLVMFuzzerTestOneInput_31(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    