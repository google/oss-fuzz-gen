#include <sys/stat.h>
#include "sqlite3.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

int LLVMFuzzerTestOneInput_62(const uint8_t *data, size_t size) {
    sqlite3 *db;
    int rc;
    
    // Open a new in-memory database
    const char vfalotux[1024] = "npmue";
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of sqlite3_open
    rc = sqlite3_open(vfalotux, &db);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
    if (rc != SQLITE_OK) {
        return 0;
    }

    // If there's data, execute it as SQL
    if (size > 0) {
        char *errMsg = 0;
        
        // Ensure the data is null-terminated before passing it to sqlite3_exec
        char *sql = (char *)malloc(size + 1);
        if (sql == NULL) {
            sqlite3_close(db);
            return 0;
        }
        memcpy(sql, data, size);
        sql[size] = '\0';

        rc = sqlite3_exec(db, sql, 0, 0, &errMsg);
        if (errMsg) {
            sqlite3_free(errMsg);
        }

        free(sql);
    }

    // Call the function-under-test
    int errcode = sqlite3_errcode(db);

    // Use the errcode in some way to avoid unused variable warning
    (void)errcode;

    // Close the database
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

    LLVMFuzzerTestOneInput_62(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
