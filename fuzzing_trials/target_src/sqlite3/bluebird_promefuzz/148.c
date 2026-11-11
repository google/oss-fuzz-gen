#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sqlite3.h"
#include <stdarg.h>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

static char *custom_vmprintf(const char *format, ...) {
    va_list args;
    va_start(args, format);
    char *result = sqlite3_vmprintf(format, args);
    va_end(args);
    return result;
}

int LLVMFuzzerTestOneInput_148(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize SQLite
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    const char *tail = NULL;
    char *sql = NULL;
    char *expandedSql = NULL;
    int rc;

    // Create a dummy file for any file-based operations
    write_dummy_file(Data, Size);

    // Open an in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Use custom_vmprintf to format a string
    sql = custom_vmprintf("%.*s", (int)Size, Data);

    if (sql) {
        // Prepare the SQL statement
        rc = sqlite3_prepare_v2(db, sql, -1, &stmt, &tail);
        if (rc == SQLITE_OK) {
            // Retrieve the last error message
            const char *errmsg = sqlite3_errmsg(db);

            // Get the expanded SQL
            expandedSql = sqlite3_expanded_sql(stmt);

            // Free the expanded SQL string
            sqlite3_free(expandedSql);
        }
    }

    // Free the formatted SQL string
    sqlite3_free(sql);

    // Finalize the statement
    if (stmt) {
        sqlite3_finalize(stmt);
    }

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

    LLVMFuzzerTestOneInput_148(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
