#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sqlite3.h"

static sqlite3 *open_database() {
    sqlite3 *db = NULL;
    sqlite3_open(":memory:", &db);
    return db;
}

static sqlite3_blob *open_blob(sqlite3 *db) {
    sqlite3_blob *blob = NULL;
    sqlite3_exec(db, "CREATE TABLE test (id INTEGER PRIMARY KEY, data BLOB);", NULL, NULL, NULL);
    sqlite3_exec(db, "INSERT INTO test (data) VALUES (zeroblob(10));", NULL, NULL, NULL);
    sqlite3_blob_open(db, "main", "test", "data", 1, 1, &blob);
    return blob;
}

int LLVMFuzzerTestOneInput_85(const uint8_t *Data, size_t Size) {
    sqlite3 *db = open_database();
    if (!db) return 0;

    // Step 1: sqlite3_errmsg
    const char *errmsg = sqlite3_errmsg(db);

    // Step 2: sqlite3_blob_reopen
    sqlite3_blob *blob = open_blob(db);
    if (blob) {
        sqlite3_int64 new_rowid = Size >= sizeof(sqlite3_int64) ? *((sqlite3_int64 *)Data) : 1;
        sqlite3_blob_reopen(blob, new_rowid);

        // Step 3: sqlite3_blob_bytes
        int blob_size = sqlite3_blob_bytes(blob);

        // Step 4: sqlite3_realloc64
        void *pOld = sqlite3_malloc(10);  // Use sqlite3_malloc instead of malloc
        if (pOld) {
            sqlite3_uint64 new_size = Size >= sizeof(sqlite3_uint64) ? *((sqlite3_uint64 *)Data) : 20;
            void *pNew = sqlite3_realloc64(pOld, new_size);
            if (pNew || new_size == 0) { // Check if realloc was successful or new_size is zero
                pOld = pNew;
            }
            sqlite3_free(pOld);
        }

        // Step 5: sqlite3_randomness
        void *random_buffer = malloc(blob_size);
        if (random_buffer) {
            sqlite3_randomness(blob_size, random_buffer);
            free(random_buffer);
        }

        sqlite3_blob_close(blob);
    }

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

    LLVMFuzzerTestOneInput_85(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
