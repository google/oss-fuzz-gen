#include <stdint.h>
#include <sqlite3.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_303(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    sqlite3 *source_db = NULL;
    sqlite3 *dest_db = NULL;
    sqlite3_backup *backup = NULL;
    int pages = 1; // Default number of pages to copy

    // Open source and destination databases in memory
    if (sqlite3_open(":memory:", &source_db) != SQLITE_OK) {
        return 0;
    }
    if (sqlite3_open(":memory:", &dest_db) != SQLITE_OK) {
        sqlite3_close(source_db);
        return 0;
    }

    // Create a simple table in the source database
    if (sqlite3_exec(source_db, "CREATE TABLE test(id INTEGER PRIMARY KEY, value TEXT);", NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_close(source_db);
        sqlite3_close(dest_db);
        return 0;
    }

    // Insert some data into the source database
    if (sqlite3_exec(source_db, "INSERT INTO test(value) VALUES('fuzzing');", NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_close(source_db);
        sqlite3_close(dest_db);
        return 0;
    }

    // Initialize the backup object
    backup = sqlite3_backup_init(dest_db, "main", source_db, "main");
    if (backup == NULL) {
        sqlite3_close(source_db);
        sqlite3_close(dest_db);
        return 0;
    }

    // Fuzz the number of pages to copy
    if (size > 0) {
        pages = data[0] % 10; // Limit to a small number of pages for fuzzing
    }

    // Call the function-under-test
    sqlite3_backup_step(backup, pages);

    // Clean up
    sqlite3_backup_finish(backup);
    sqlite3_close(source_db);
    sqlite3_close(dest_db);

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

    LLVMFuzzerTestOneInput_303(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
