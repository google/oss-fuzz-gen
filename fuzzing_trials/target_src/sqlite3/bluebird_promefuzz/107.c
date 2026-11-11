#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "sqlite3.h"

static int dummy_callback(void *NotUsed, int argc, char **argv, char **azColName) {
    return 0;
}

int LLVMFuzzerTestOneInput_107(const uint8_t *Data, size_t Size) {
    sqlite3 *db = NULL;
    int rc;
    char *errMsg = NULL;

    // Prepare a filename
    char filename[256];
    snprintf(filename, sizeof(filename), "./dummy_file_%zu.db", Size);

    // Ensure null-termination for safety
    filename[sizeof(filename) - 1] = '\0';

    // Try opening a database connection
    rc = sqlite3_open(filename, &db);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Execute a dummy SQL statement
    const char *sql = "CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, value TEXT);";
    rc = sqlite3_exec(db, sql, dummy_callback, 0, &errMsg);
    if (rc != SQLITE_OK) {
        sqlite3_free(errMsg);
        sqlite3_close(db);
        return 0;
    }

    // Deserialize test
    unsigned char *pData = (unsigned char *)sqlite3_malloc(Size);
    if (pData) {
        memcpy(pData, Data, Size);
        rc = sqlite3_deserialize(db, "main", pData, Size, Size, SQLITE_DESERIALIZE_FREEONCLOSE);
        if (rc != SQLITE_OK) {
            sqlite3_free(pData);
        }
    }

    // Check changes
    int changes = sqlite3_changes(db);

    // Cleanup
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

    LLVMFuzzerTestOneInput_107(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
