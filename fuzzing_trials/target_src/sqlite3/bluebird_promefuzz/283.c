#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sqlite3.h"
#include <stdint.h>
#include <stddef.h>

static sqlite3* initialize_database() {
    sqlite3 *db;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return NULL;
    }
    return db;
}

static void cleanup_database(sqlite3 *db) {
    if (db) {
        sqlite3_close(db);
    }
}

int LLVMFuzzerTestOneInput_283(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) {
        return 0;
    }

    sqlite3 *db = initialize_database();
    if (!db) {
        return 0;
    }

    int mutexType = *(int*)Data;
    if (mutexType < SQLITE_MUTEX_FAST || mutexType > SQLITE_MUTEX_RECURSIVE) {
        cleanup_database(db);
        return 0;
    }

    sqlite3_mutex *mutex = sqlite3_mutex_alloc(mutexType);
    if (mutex) {
        sqlite3_mutex_enter(mutex);
        if (sqlite3_mutex_held(mutex)) {
            sqlite3_mutex_leave(mutex);
        }
        sqlite3_mutex_free(mutex);
    }

    sqlite3_mutex *dbMutex = sqlite3_db_mutex(db);
    if (dbMutex) {
        sqlite3_mutex_enter(dbMutex);
        if (sqlite3_mutex_held(dbMutex)) {
            sqlite3_mutex_leave(dbMutex);
        }
    }

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_283(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
