#include <stdint.h>
#include <sqlite3.h>
#include <string.h>
#include <stdlib.h> // Include for malloc and free

int LLVMFuzzerTestOneInput_209(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for a meaningful test
    if (size < 2) {
        return 0;
    }

    // Initialize SQLite statement
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT * FROM test WHERE id = ?1";

    // Create a temporary SQLite database in memory
    sqlite3 *db;
    sqlite3_open(":memory:", &db);

    // Prepare the SQL statement
    sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);

    // Ensure the data is null-terminated for use as a string
    char *param_name = (char *)malloc(size + 1);
    memcpy(param_name, data, size);
    param_name[size] = '\0';

    // Call the function-under-test
    int index = sqlite3_bind_parameter_index(stmt, param_name);

    // Clean up
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    free(param_name);

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

    LLVMFuzzerTestOneInput_209(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
