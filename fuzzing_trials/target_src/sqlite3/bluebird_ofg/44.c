#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>  // Include for size_t
#include "sqlite3.h"
#include <stdlib.h>  // Include for malloc and free
#include <string.h>  // Include for memcpy

int LLVMFuzzerTestOneInput_44(const uint8_t *data, size_t size) {
    sqlite3 *db;
    int rc;
    
    // Initialize SQLite database in memory
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Execute some SQL commands if data is available
    if (size > 0) {
        // Allocate memory for the SQL command and ensure it's null-terminated
        char *sqlCommand = (char *)malloc(size + 1);
        if (sqlCommand == NULL) {
            sqlite3_close(db);
            return 0;
        }
        memcpy(sqlCommand, data, size);
        sqlCommand[size] = '\0';  // Null-terminate the string

        char *errMsg = 0;
        // Use the input data as an SQL command
        sqlite3_exec(db, sqlCommand, 0, 0, &errMsg);
        if (errMsg) {
            sqlite3_free(errMsg);
        }

        free(sqlCommand);  // Free the allocated memory
    }

    // Call the function to fuzz
    sqlite3_db_release_memory(db);

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

    LLVMFuzzerTestOneInput_44(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
