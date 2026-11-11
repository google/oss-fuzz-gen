#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_213(const uint8_t *data, size_t size) {
    // Initialize an SQLite memory context
    sqlite3 *db;
    sqlite3_open(":memory:", &db);

    // Ensure that the data is not null and size is greater than zero
    if (data != NULL && size > 0) {
        // Prepare a SQL statement using the input data
        sqlite3_stmt *stmt;
        const char *tail;
        if (sqlite3_prepare_v2(db, (const char *)data, (int)size, &stmt, &tail) == SQLITE_OK) {
            // Step through the statement to execute it
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                // Access data from the result row if needed
                const unsigned char *text = sqlite3_column_text(stmt, 0);
                if (text != NULL) {
                    volatile const unsigned char *prevent_optimization = text;
                    (void)prevent_optimization;
                }
            }
            // Finalize the statement to release resources
            sqlite3_finalize(stmt);
        }
    }

    // Clean up
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

    LLVMFuzzerTestOneInput_213(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
