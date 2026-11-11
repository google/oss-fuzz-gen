#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h> // Include this for the close() and remove() functions
#include <stdlib.h> // Include this for the mkstemp() function

int LLVMFuzzerTestOneInput_127(const uint8_t *data, size_t size) {
    // Create a temporary database file
    char db_name[] = "/tmp/fuzzdbXXXXXX";
    int fd = mkstemp(db_name);
    if (fd == -1) {
        return 0;
    }
    close(fd);

    sqlite3 *db = NULL;
    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
    const char *vfs = NULL;

    // Open the SQLite database
    int result = sqlite3_open_v2(db_name, &db, flags, vfs);
    if (result != SQLITE_OK || db == NULL) {
        remove(db_name);
        return 0;
    }

    // Prepare and execute an SQL statement using the input data
    sqlite3_stmt *stmt;
    const char *sql = "CREATE TABLE IF NOT EXISTS fuzz (data BLOB);";
    result = sqlite3_exec(db, sql, 0, 0, 0);
    if (result != SQLITE_OK) {
        sqlite3_close(db);
        remove(db_name);
        return 0;
    }

    // Insert the input data into the table
    sql = "INSERT INTO fuzz (data) VALUES (?);";
    result = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if (result == SQLITE_OK) {
        sqlite3_bind_blob(stmt, 1, data, size, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    // Close the database
    sqlite3_close(db);

    // Remove the temporary database file
    remove(db_name);

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

    LLVMFuzzerTestOneInput_127(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
