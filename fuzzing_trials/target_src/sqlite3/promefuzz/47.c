// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_open at sqlite3.c:174695:16 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
// sqlite3_txn_state at sqlite3.c:172326:16 in sqlite3.h
// sqlite3_backup_init at sqlite3.c:69968:28 in sqlite3.h
// sqlite3_backup_step at sqlite3.c:70142:16 in sqlite3.h
// sqlite3_backup_finish at sqlite3.c:70399:16 in sqlite3.h
// sqlite3_wal_checkpoint at sqlite3.c:173627:16 in sqlite3.h
// sqlite3_wal_autocheckpoint at sqlite3.c:173506:16 in sqlite3.h
// sqlite3_wal_hook at sqlite3.c:173527:18 in sqlite3.h
// sqlite3_wal_checkpoint_v2 at sqlite3.c:173557:16 in sqlite3.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sqlite3.h>
#include <assert.h>

static void initialize_database(sqlite3 **db) {
    int rc = sqlite3_open(":memory:", db);
    assert(rc == SQLITE_OK);
}

static void cleanup_database(sqlite3 *db) {
    sqlite3_close(db);
}

static void fuzz_sqlite3_txn_state(sqlite3 *db, const uint8_t *Data, size_t Size) {
    char *zSchema = NULL;
    if (Size > 0) {
        zSchema = (char *)malloc(Size + 1);
        memcpy(zSchema, Data, Size);
        zSchema[Size] = '\0';
    }
    int state = sqlite3_txn_state(db, zSchema);
    (void)state; // Suppress unused variable warning
    free(zSchema);
}

static void fuzz_sqlite3_backup_step(sqlite3 *db, const uint8_t *Data, size_t Size) {
    sqlite3_backup *backup = sqlite3_backup_init(db, "main", db, "temp");
    if (backup) {
        int nPage = (Size > 0) ? Data[0] : 0;
        int rc = sqlite3_backup_step(backup, nPage);
        (void)rc; // Suppress unused variable warning
        sqlite3_backup_finish(backup);
    }
}

static void fuzz_sqlite3_wal_checkpoint(sqlite3 *db, const uint8_t *Data, size_t Size) {
    char *zDb = NULL;
    if (Size > 0) {
        zDb = (char *)malloc(Size + 1);
        memcpy(zDb, Data, Size);
        zDb[Size] = '\0';
    }
    int rc = sqlite3_wal_checkpoint(db, zDb);
    (void)rc; // Suppress unused variable warning
    free(zDb);
}

static void fuzz_sqlite3_wal_autocheckpoint(sqlite3 *db, const uint8_t *Data, size_t Size) {
    int N = (Size > 0) ? Data[0] : 0;
    int rc = sqlite3_wal_autocheckpoint(db, N);
    (void)rc; // Suppress unused variable warning
}

static int wal_hook_callback(void *pArg, sqlite3 *db, const char *zDb, int nPages) {
    (void)pArg;
    (void)db;
    (void)zDb;
    (void)nPages;
    return SQLITE_OK;
}

static void fuzz_sqlite3_wal_hook(sqlite3 *db, const uint8_t *Data, size_t Size) {
    void *prev = sqlite3_wal_hook(db, wal_hook_callback, NULL);
    (void)prev; // Suppress unused variable warning
}

static void fuzz_sqlite3_wal_checkpoint_v2(sqlite3 *db, const uint8_t *Data, size_t Size) {
    char *zDb = NULL;
    if (Size > 0) {
        zDb = (char *)malloc(Size + 1);
        memcpy(zDb, Data, Size);
        zDb[Size] = '\0';
    }
    int eMode = (Size > 1) ? Data[1] : SQLITE_CHECKPOINT_PASSIVE;
    int pnLog = 0, pnCkpt = 0;
    int rc = sqlite3_wal_checkpoint_v2(db, zDb, eMode, &pnLog, &pnCkpt);
    (void)rc; // Suppress unused variable warning
    free(zDb);
}

int LLVMFuzzerTestOneInput_47(const uint8_t *Data, size_t Size) {
    sqlite3 *db;
    initialize_database(&db);

    fuzz_sqlite3_txn_state(db, Data, Size);
    fuzz_sqlite3_backup_step(db, Data, Size);
    fuzz_sqlite3_wal_checkpoint(db, Data, Size);
    fuzz_sqlite3_wal_autocheckpoint(db, Data, Size);
    fuzz_sqlite3_wal_hook(db, Data, Size);
    fuzz_sqlite3_wal_checkpoint_v2(db, Data, Size);

    cleanup_database(db);
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

        LLVMFuzzerTestOneInput_47(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    