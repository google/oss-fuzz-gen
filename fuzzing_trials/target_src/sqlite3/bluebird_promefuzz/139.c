#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sqlite3.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int dummy_callback(void *NotUsed, int argc, char **argv, char **azColName) {
    return 0;
}

int LLVMFuzzerTestOneInput_139(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    sqlite3 *db = NULL;
    char *errMsg = NULL;
    int rc;
    int cur, hiwtr;
    char *formattedStr1 = NULL;
    char *formattedStr2 = NULL;

    // Ensure the input data is null-terminated
    char *sqlInput = (char *)malloc(Size + 1);
    if (!sqlInput) return 0;
    memcpy(sqlInput, Data, Size);
    sqlInput[Size] = '\0';

    // Step 1: sqlite3_config
    rc = sqlite3_config(SQLITE_CONFIG_SINGLETHREAD);
    if (rc != SQLITE_OK && rc != SQLITE_MISUSE) {
        free(sqlInput);
        return 0;
    }

    // Step 2: sqlite3_open
    rc = sqlite3_open("./dummy_file", &db);
    if (rc != SQLITE_OK) {
        free(sqlInput);
        return 0;
    }

    // Step 3: sqlite3_errmsg
    const char *errmsg = sqlite3_errmsg(db);

    // Step 4: sqlite3_exec
    rc = sqlite3_exec(db, sqlInput, dummy_callback, 0, &errMsg);
    if (rc != SQLITE_OK && errMsg) {
        sqlite3_free(errMsg);
        errMsg = NULL;
    }

    // Step 5: sqlite3_free
    sqlite3_free(errMsg);

    // Step 6-14: sqlite3_db_status
    for (int i = 0; i < 9; i++) {
        rc = sqlite3_db_status(db, SQLITE_DBSTATUS_LOOKASIDE_USED, &cur, &hiwtr, 0);
        if (rc != SQLITE_OK) {
            break;
        }
    }

    // Step 15: sqlite3_close
    rc = sqlite3_close(db);
    if (rc != SQLITE_OK) {
        free(sqlInput);
        return 0;
    }

    // Step 16-20: sqlite3_status
    for (int i = 0; i < 5; i++) {
        rc = sqlite3_status(SQLITE_STATUS_MEMORY_USED, &cur, &hiwtr, 0);
        if (rc != SQLITE_OK) {
            break;
        }
    }

    // Step 21: sqlite3_mprintf
    formattedStr1 = sqlite3_mprintf("%s", "fuzzing with sqlite3");
    sqlite3_free(formattedStr1);

    // Step 22: sqlite3_mprintf
    formattedStr2 = sqlite3_mprintf("%s", "another test");
    sqlite3_free(formattedStr2);

    // Step 23: sqlite3_open
    rc = sqlite3_open("./dummy_file", &db);
    if (rc != SQLITE_OK) {
        free(sqlInput);
        return 0;
    }

    // Step 24: sqlite3_errmsg
    errmsg = sqlite3_errmsg(db);

    // Step 25-27: sqlite3_exec
    for (int i = 0; i < 3; i++) {
        rc = sqlite3_exec(db, sqlInput, dummy_callback, 0, &errMsg);
        if (rc != SQLITE_OK && errMsg) {
            sqlite3_free(errMsg);
            errMsg = NULL;
        }
    }

    // Step 28: sqlite3_free
    sqlite3_free(errMsg);

    // Step 29: sqlite3_close
    rc = sqlite3_close(db);

    free(sqlInput);
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

    LLVMFuzzerTestOneInput_139(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
