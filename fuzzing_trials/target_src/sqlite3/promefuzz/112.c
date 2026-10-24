// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_open at sqlite3.c:174695:16 in sqlite3.h
// sqlite3_exec at sqlite3.c:126811:16 in sqlite3.h
// sqlite3_free at sqlite3.c:17452:17 in sqlite3.h
// sqlite3_open at sqlite3.c:174695:16 in sqlite3.h
// sqlite3_backup_init at sqlite3.c:69968:28 in sqlite3.h
// sqlite3_backup_step at sqlite3.c:70142:16 in sqlite3.h
// sqlite3_backup_finish at sqlite3.c:70399:16 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
// sqlite3_serialize at sqlite3.c:41164:27 in sqlite3.h
// sqlite3_deserialize at sqlite3.c:41253:16 in sqlite3.h
// sqlite3_free at sqlite3.c:17452:17 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
#include <sqlite3.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
    return 0;
}

int LLVMFuzzerTestOneInput_112(const unsigned char *Data, size_t Size) {
    if (Size == 0) return 0;

    // Ensure null-terminated SQL input
    char *sql = (char *)malloc(Size + 1);
    if (!sql) return 0;
    memcpy(sql, Data, Size);
    sql[Size] = '\0';

    // Initialize variables
    sqlite3 *db = NULL;
    sqlite3 *backupDb = NULL;
    sqlite3_backup *backup = NULL;
    char *errMsg = NULL;
    int rc;

    // Prepare filename
    char filename[256];
    snprintf(filename, sizeof(filename), "./dummy_file_%zu", Size);

    // Open a database connection
    rc = sqlite3_open(filename, &db);
    if (rc != SQLITE_OK || db == NULL) {
        free(sql);
        return 0;
    }

    // Execute some SQL
    rc = sqlite3_exec(db, sql, callback, 0, &errMsg);
    if (rc != SQLITE_OK && errMsg != NULL) {
        sqlite3_free(errMsg);
    }

    // Backup operation
    rc = sqlite3_open(":memory:", &backupDb);
    if (rc == SQLITE_OK && backupDb != NULL) {
        backup = sqlite3_backup_init(backupDb, "main", db, "main");
        if (backup) {
            while ((rc = sqlite3_backup_step(backup, 5)) == SQLITE_OK) {
                // Do nothing, just step
            }
            sqlite3_backup_finish(backup);
        }
        sqlite3_close(backupDb);
    }

    // Deserialize operation
    unsigned char *serializedData;
    sqlite3_int64 serializedSize;
    serializedData = sqlite3_serialize(db, "main", &serializedSize, 0);
    if (serializedData) {
        rc = sqlite3_deserialize(db, "main", serializedData, serializedSize, serializedSize, 0);
        if (rc != SQLITE_OK) {
            sqlite3_free(serializedData);
        }
    }

    // Close the database connection
    sqlite3_close(db);

    // Free allocated memory
    free(sql);

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

        LLVMFuzzerTestOneInput_112(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    