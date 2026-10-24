// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_busy_timeout at sqlite3.c:172853:16 in sqlite3.h
// sqlite3_sleep at sqlite3.c:175133:16 in sqlite3.h
// sqlite3_changes at sqlite3.c:172160:16 in sqlite3.h
// sqlite3_threadsafe at sqlite3.c:171135:16 in sqlite3.h
// sqlite3_global_recover at sqlite3.c:174934:16 in sqlite3.h
// sqlite3_db_status at sqlite3.c:11036:16 in sqlite3.h
// sqlite3_open at sqlite3.c:174695:16 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static void fuzz_sqlite3_busy_timeout(sqlite3 *db, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return; // Ensure there's enough data for an int
    int ms;
    memcpy(&ms, Data, sizeof(int));
    sqlite3_busy_timeout(db, ms);
}

static void fuzz_sqlite3_sleep(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return; // Ensure there's enough data for an int
    int ms;
    memcpy(&ms, Data, sizeof(int));
    sqlite3_sleep(ms);
}

static void fuzz_sqlite3_changes(sqlite3 *db) {
    sqlite3_changes(db);
}

static void fuzz_sqlite3_threadsafe() {
    sqlite3_threadsafe();
}

static void fuzz_sqlite3_global_recover() {
    sqlite3_global_recover();
}

static void fuzz_sqlite3_db_status(sqlite3 *db, const uint8_t *Data, size_t Size) {
    if (Size < 3 * sizeof(int)) return; // Ensure there's enough data for three ints
    int op, resetFlg;
    int cur = 0, hiwtr = 0;
    memcpy(&op, Data, sizeof(int));
    memcpy(&resetFlg, Data + sizeof(int), sizeof(int));
    sqlite3_db_status(db, op, &cur, &hiwtr, resetFlg);
}

int LLVMFuzzerTestOneInput_105(const uint8_t *Data, size_t Size) {
    sqlite3 *db;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    fuzz_sqlite3_busy_timeout(db, Data, Size);
    fuzz_sqlite3_sleep(Data, Size);
    fuzz_sqlite3_changes(db);
    fuzz_sqlite3_threadsafe();
    fuzz_sqlite3_global_recover();
    fuzz_sqlite3_db_status(db, Data, Size);

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

        LLVMFuzzerTestOneInput_105(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    