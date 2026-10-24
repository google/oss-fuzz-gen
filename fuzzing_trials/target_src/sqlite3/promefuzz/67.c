// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_bind_zeroblob64 at sqlite3.c:80242:16 in sqlite3.h
// sqlite3_bind_blob64 at sqlite3.c:80094:16 in sqlite3.h
// sqlite3_bind_null at sqlite3.c:80129:16 in sqlite3.h
// sqlite3_bind_zeroblob at sqlite3.c:80227:16 in sqlite3.h
// sqlite3_bind_blob at sqlite3.c:80082:16 in sqlite3.h
// sqlite3_bind_double at sqlite3.c:80104:16 in sqlite3.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sqlite3.h>

static void dummy_destructor(void* data) {
    // Dummy destructor function
}

int LLVMFuzzerTestOneInput_67(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int) + sizeof(double) + sizeof(sqlite3_uint64)) {
        return 0; // Not enough data to proceed
    }

    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;
    char *errMsg = 0;

    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    rc = sqlite3_exec(db, "CREATE TABLE test (id INTEGER PRIMARY KEY, data BLOB);", 0, 0, &errMsg);
    if (rc != SQLITE_OK) {
        sqlite3_free(errMsg);
        sqlite3_close(db);
        return 0;
    }

    rc = sqlite3_prepare_v2(db, "INSERT INTO test (data) VALUES (?);", -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    int paramIndex = Data[0] % 10; // Random parameter index
    double doubleValue = *((double*)(Data + 1));
    sqlite3_uint64 blobSize = *((sqlite3_uint64*)(Data + 1 + sizeof(double)));

    // Ensure blobData points to a valid memory region within Data
    const void *blobData = (const void*)(Data + 1 + sizeof(double) + sizeof(sqlite3_uint64));
    size_t maxBlobDataSize = Size - (1 + sizeof(double) + sizeof(sqlite3_uint64));
    if (blobSize > maxBlobDataSize) {
        blobSize = maxBlobDataSize; // Adjust blobSize to avoid out-of-bounds access
    }

    // Fuzzing sqlite3_bind_null
    sqlite3_bind_null(stmt, paramIndex);

    // Fuzzing sqlite3_bind_zeroblob64
    sqlite3_bind_zeroblob64(stmt, paramIndex, blobSize);

    // Fuzzing sqlite3_bind_blob64
    sqlite3_bind_blob64(stmt, paramIndex, blobData, blobSize, dummy_destructor);

    // Fuzzing sqlite3_bind_zeroblob
    sqlite3_bind_zeroblob(stmt, paramIndex, (int)(blobSize % 1000)); // Limiting size to 1000 for practical reasons

    // Fuzzing sqlite3_bind_double
    sqlite3_bind_double(stmt, paramIndex, doubleValue);

    // Fuzzing sqlite3_bind_blob
    sqlite3_bind_blob(stmt, paramIndex, blobData, (int)(blobSize % 1000), dummy_destructor);

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

        LLVMFuzzerTestOneInput_67(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    