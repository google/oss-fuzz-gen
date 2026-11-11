#include <stdint.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_252(const uint8_t *data, size_t size) {
    // Ensure the data is not empty
    if (size > 0) {
        // Create a new SQLite memory database
        sqlite3 *db;
        sqlite3_open(":memory:", &db);

        // Prepare a dummy SQL statement
        sqlite3_stmt *stmt;
        const char *sql = "SELECT ?";

        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            // Copy the input data into a buffer
            void *buffer = malloc(size);
            if (buffer != NULL) {
                memcpy(buffer, data, size);

                // Bind the buffer to the SQL statement
                sqlite3_bind_blob(stmt, 1, buffer, size, SQLITE_TRANSIENT);

                // Step through the statement to trigger the function-under-test
                sqlite3_step(stmt);

                // Free the buffer
                free(buffer);
            }

            // Finalize the statement
            sqlite3_finalize(stmt);
        }

        // Close the database
        sqlite3_close(db);
    }

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

    LLVMFuzzerTestOneInput_252(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
