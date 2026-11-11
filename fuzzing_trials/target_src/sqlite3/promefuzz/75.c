// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_open at sqlite3.c:174695:16 in sqlite3.h
// sqlite3_prepare_v2 at sqlite3.c:132572:16 in sqlite3.h
// sqlite3_bind_text at sqlite3.c:80158:16 in sqlite3.h
// sqlite3_column_value at sqlite3.c:79754:27 in sqlite3.h
// sqlite3_finalize at sqlite3.c:78432:16 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
// sqlite3_value_bytes16 at sqlite3.c:78531:16 in sqlite3.h
// sqlite3_value_nochange at sqlite3.c:78667:16 in sqlite3.h
// sqlite3_value_type at sqlite3.c:78578:16 in sqlite3.h
// sqlite3_value_encoding at sqlite3.c:78662:16 in sqlite3.h
// sqlite3_value_numeric_type at sqlite3.c:81688:16 in sqlite3.h
// sqlite3_value_frombind at sqlite3.c:78672:16 in sqlite3.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sqlite3.h>

static sqlite3_value* create_sqlite3_value(const uint8_t *Data, size_t Size) {
    sqlite3_value *val;
    sqlite3 *db;
    sqlite3_open(":memory:", &db);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "SELECT ?", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, (const char *)Data, Size, SQLITE_TRANSIENT);

    val = (sqlite3_value *)sqlite3_column_value(stmt, 0);

    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return val;
}

int LLVMFuzzerTestOneInput_75(const uint8_t *Data, size_t Size) {
    sqlite3_value *val = create_sqlite3_value(Data, Size);
    if (!val) return 0;

    // 1. Test sqlite3_value_bytes16
    int bytes16 = sqlite3_value_bytes16(val);

    // 2. Test sqlite3_value_nochange
    int nochange = sqlite3_value_nochange(val);

    // 3. Test sqlite3_value_type
    int type = sqlite3_value_type(val);

    // 4. Test sqlite3_value_encoding if type is TEXT
    int encoding = 0;
    if (type == SQLITE_TEXT) {
        encoding = sqlite3_value_encoding(val);
    }

    // 5. Test sqlite3_value_numeric_type
    int numeric_type = sqlite3_value_numeric_type(val);

    // 6. Test sqlite3_value_frombind
    int frombind = sqlite3_value_frombind(val);

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

        LLVMFuzzerTestOneInput_75(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    