#include <stdint.h>
#include <stddef.h>  // Include for size_t
#include <sqlite3.h>
#include <string.h>  // Include for memcpy

int LLVMFuzzerTestOneInput_110(const uint8_t *data, size_t size) {
    // Declare variables
    sqlite3 *src_db = NULL;
    sqlite3 *dest_db = NULL;
    sqlite3_backup *backup = NULL;
    int rc;
    char *err_msg = NULL;

    // Initialize source and destination databases
    rc = sqlite3_open(":memory:", &src_db);
    if (rc != SQLITE_OK) goto cleanup;

    rc = sqlite3_open(":memory:", &dest_db);
    if (rc != SQLITE_OK) goto cleanup;

    // Create a table and insert fuzz data into the source database
    rc = sqlite3_exec(src_db, "CREATE TABLE test (data BLOB);", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) goto cleanup;

    // Prepare an SQL statement to insert fuzz data
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(src_db, "INSERT INTO test (data) VALUES (?);", -1, &stmt, NULL);
    if (rc != SQLITE_OK) goto cleanup;

    // Bind the input data to the SQL statement
    rc = sqlite3_bind_blob(stmt, 1, data, size, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) goto cleanup;

    // Execute the SQL statement
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) goto cleanup;

    // Finalize the statement
    sqlite3_finalize(stmt);

    // Create a backup from source to destination
    backup = sqlite3_backup_init(dest_db, "main", src_db, "main");
    if (backup == NULL) goto cleanup;

    // Perform the backup step
    rc = sqlite3_backup_step(backup, 5);
    if (rc != SQLITE_OK && rc != SQLITE_DONE) goto cleanup;

    // Call the function-under-test
    int remaining = sqlite3_backup_remaining(backup);

    // Continue with backup if needed
    while ((rc = sqlite3_backup_step(backup, 5)) == SQLITE_OK) {
        remaining = sqlite3_backup_remaining(backup);
    }

cleanup:
    // Finish the backup process
    if (backup != NULL) {
        sqlite3_backup_finish(backup);
    }

    // Close the databases
    if (src_db != NULL) {
        sqlite3_close(src_db);
    }
    if (dest_db != NULL) {
        sqlite3_close(dest_db);
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

    LLVMFuzzerTestOneInput_110(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
