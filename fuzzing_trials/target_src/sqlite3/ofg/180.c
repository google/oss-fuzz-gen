#include <stdint.h>
#include <sqlite3.h>
#include <stddef.h>

// Dummy collation function
int collation_function(void *unused, int len1, const void *str1, int len2, const void *str2) {
    return 0; // Simple comparison logic for fuzzing purposes
}

// Dummy destructor function
void destructor_function(void *unused) {
    // No operation needed for this dummy function
}

int LLVMFuzzerTestOneInput_180(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0; // Ensure there is at least one byte for the collation name
    }

    sqlite3 *db;
    int rc = sqlite3_open(":memory:", &db); // Open an in-memory database
    if (rc != SQLITE_OK) {
        return 0; // If opening the database fails, exit
    }

    // Use the first byte of data as the length of the collation name, ensure it's not zero
    size_t collation_name_len = data[0] % size;
    if (collation_name_len == 0) {
        collation_name_len = 1;
    }

    // Ensure there's enough data for the collation name
    if (size < collation_name_len + 1) {
        sqlite3_close(db);
        return 0;
    }

    // Extract the collation name from the data
    char collation_name[collation_name_len + 1];
    for (size_t i = 0; i < collation_name_len; i++) {
        collation_name[i] = data[i + 1];
    }
    collation_name[collation_name_len] = '\0'; // Null-terminate the string

    // Call the function-under-test
    sqlite3_create_collation_v2(
        db,
        collation_name,
        SQLITE_UTF8,
        NULL, // No application-specific data
        collation_function,
        destructor_function
    );

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

    LLVMFuzzerTestOneInput_180(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
