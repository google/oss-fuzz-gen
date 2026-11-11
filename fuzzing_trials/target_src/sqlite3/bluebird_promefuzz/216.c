#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sqlite3.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static void prepare_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fprintf(file, "CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT);");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_216(const uint8_t *Data, size_t Size) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int rc;
    const char *sql = "SELECT 1;";

    // Prepare environment
    prepare_dummy_file();
    rc = sqlite3_open("./dummy_file", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Set busy timeout
    int timeout = Size > 0 ? Data[0] : 0; // Use first byte of data as timeout
    sqlite3_busy_timeout(db, timeout);

    // Prepare a simple statement
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Execute the statement
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        // Fetch a column
        int value = sqlite3_column_int(stmt, 0);
        (void)value; // Suppress unused variable warning
    }

    // Finalize the statement
    sqlite3_finalize(stmt);

    // Sleep for a duration based on input data
    int sleep_time = Size > 1 ? Data[1] : 0; // Use second byte of data as sleep time
    sqlite3_sleep(sleep_time);

    // Close the database connection
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

    LLVMFuzzerTestOneInput_216(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
