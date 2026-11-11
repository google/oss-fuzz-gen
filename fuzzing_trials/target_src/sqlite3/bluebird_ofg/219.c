#include <sys/stat.h>
#include "sqlite3.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_219(const uint8_t *data, size_t size) {
    // Check if the input size is large enough to be a valid SQL statement
    if (size < 1) {
        return 0;
    }

    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
    const void *tail = NULL;
    int rc;

    // Open a temporary in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Prepare a SQL statement using the provided data
    rc = sqlite3_prepare_v2(db, (const char *)data, (int)size, &stmt, &tail);

    // Finalize the statement if it was prepared successfully
    if (stmt != NULL) {
        sqlite3_finalize(stmt);
    }

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

    LLVMFuzzerTestOneInput_219(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
