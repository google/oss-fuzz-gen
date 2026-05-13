#include <stdint.h>
#include <sqlite3.h>
#include <string.h>

int LLVMFuzzerTestOneInput_126(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0;
    }

    // Initialize SQLite database in memory
    sqlite3 *source_db = NULL;
    sqlite3 *dest_db = NULL;
    sqlite3_backup *backup = NULL;
    int rc;

    rc = sqlite3_open(":memory:", &source_db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    rc = sqlite3_open(":memory:", &dest_db);
    if (rc != SQLITE_OK) {
        sqlite3_close(source_db);
        return 0;
    }

    // Create a table in the source database
    const char *create_table_sql = "CREATE TABLE test(id INTEGER PRIMARY KEY, value TEXT);";
    rc = sqlite3_exec(source_db, create_table_sql, 0, 0, 0);
    if (rc != SQLITE_OK) {
        sqlite3_close(source_db);
        sqlite3_close(dest_db);
        return 0;
    }

    // Insert some data into the source database
    const char *insert_sql = "INSERT INTO test(value) VALUES('test');";
    rc = sqlite3_exec(source_db, insert_sql, 0, 0, 0);
    if (rc != SQLITE_OK) {
        sqlite3_close(source_db);
        sqlite3_close(dest_db);
        return 0;
    }

    // Start the backup process
    backup = sqlite3_backup_init(dest_db, "main", source_db, "main");
    if (backup) {
        // Call the function under test
        int page_count = sqlite3_backup_pagecount(backup);

        // Perform the backup step
        sqlite3_backup_step(backup, 1);
        sqlite3_backup_finish(backup);
    }

    // Clean up
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

    LLVMFuzzerTestOneInput_126(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
