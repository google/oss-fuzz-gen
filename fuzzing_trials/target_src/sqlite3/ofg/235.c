#include <stdint.h>
#include <stdlib.h>
#include <sqlite3.h>

// Define a simple callback function for the progress handler
static int progress_handler_callback(void *data) {
    // Just return 0 to continue execution
    return 0;
}

int LLVMFuzzerTestOneInput_235(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    int rc;
    int nOps = 100;  // Set a default number of operations before the handler is called

    // Open an in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;  // If the database can't be opened, exit
    }

    // Use the first byte of the data as the number of operations if size is greater than 0
    if (size > 0) {
        nOps = data[0];
    }

    // Set the progress handler with the callback
    sqlite3_progress_handler(db, nOps, progress_handler_callback, NULL);

    // Execute a simple SQL command to trigger the progress handler
    sqlite3_exec(db, "CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT);", NULL, NULL, NULL);

    // Close the database
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

    LLVMFuzzerTestOneInput_235(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
