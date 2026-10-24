// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_open at sqlite3.c:174695:16 in sqlite3.h
// sqlite3_prepare_v2 at sqlite3.c:132572:16 in sqlite3.h
// sqlite3_bind_blob at sqlite3.c:80082:16 in sqlite3.h
// sqlite3_step at sqlite3.c:79246:16 in sqlite3.h
// sqlite3_column_value at sqlite3.c:79754:27 in sqlite3.h
// sqlite3_vtab_in_first at sqlite3.c:79420:16 in sqlite3.h
// sqlite3_vtab_in_next at sqlite3.c:79428:16 in sqlite3.h
// sqlite3_value_type at sqlite3.c:78578:16 in sqlite3.h
// sqlite3_value_nochange at sqlite3.c:78667:16 in sqlite3.h
// sqlite3_value_encoding at sqlite3.c:78662:16 in sqlite3.h
// sqlite3_value_frombind at sqlite3.c:78672:16 in sqlite3.h
// sqlite3_finalize at sqlite3.c:78432:16 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_108(const uint8_t *Data, size_t Size) {
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

        if(size < 1 + 1)
            exit(0);

        data = (uint8_t *)malloc((size_t)size);
        if(data == NULL)
            exit(0);

        if(fread(data, (size_t)size, 1, f) != 1)
            exit(0);

        LLVMFuzzerTestOneInput_108(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    