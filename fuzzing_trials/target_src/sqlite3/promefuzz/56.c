// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_open at sqlite3.c:174695:16 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
// sqlite3_exec at sqlite3.c:126811:16 in sqlite3.h
// sqlite3_free at sqlite3.c:17452:17 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
// sqlite3_malloc at sqlite3.c:17377:18 in sqlite3.h
// sqlite3_deserialize at sqlite3.c:41253:16 in sqlite3.h
// sqlite3_free at sqlite3.c:17452:17 in sqlite3.h
// sqlite3_changes at sqlite3.c:172160:16 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
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

int LLVMFuzzerTestOneInput_56(const uint8_t *Data, size_t Size) {
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

        if(size < 1 + 1)
            exit(0);

        data = (uint8_t *)malloc((size_t)size);
        if(data == NULL)
            exit(0);

        if(fread(data, (size_t)size, 1, f) != 1)
            exit(0);

        LLVMFuzzerTestOneInput_56(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    