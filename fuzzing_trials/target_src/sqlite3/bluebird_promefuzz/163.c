#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"

int LLVMFuzzerTestOneInput_163(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return 0;

    // Create a dummy database connection
    sqlite3 *db;
    sqlite3_open(":memory:", &db);

    // Prepare a dummy sqlite3_value
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "SELECT ?1", -1, &stmt, NULL);
    sqlite3_bind_blob(stmt, 1, Data, Size, SQLITE_TRANSIENT);

    // Retrieve the sqlite3_value from the statement
    sqlite3_step(stmt);
    sqlite3_value *pVal = (sqlite3_value*)sqlite3_column_value(stmt, 0);

    // Fuzz sqlite3_vtab_in_first
    sqlite3_value *pOut = NULL;
    int rc = sqlite3_vtab_in_first(pVal, &pOut);
    if (rc == SQLITE_OK && pOut) {
        // Fuzz sqlite3_vtab_in_next if first succeeded
        while (rc == SQLITE_OK && pOut) {
            rc = sqlite3_vtab_in_next(pVal, &pOut);
        }
    }

    // Fuzz sqlite3_value_type
    int type = sqlite3_value_type(pVal);

    // Fuzz sqlite3_value_nochange
    int noChange = sqlite3_value_nochange(pVal);

    // Fuzz sqlite3_value_encoding if type is TEXT
    if (type == SQLITE_TEXT) {
        int encoding = sqlite3_value_encoding(pVal);
    }

    // Fuzz sqlite3_value_frombind
    int fromBind = sqlite3_value_frombind(pVal);

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_163(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
