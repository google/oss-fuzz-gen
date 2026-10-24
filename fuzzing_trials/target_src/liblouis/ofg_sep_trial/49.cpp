#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C" {
    // Include the necessary header for the function-under-test
    void lou_indexTables(const char **);
}

extern "C" int LLVMFuzzerTestOneInput_49(const uint8_t *data, size_t size) {
    // Ensure there is enough data to work with
    if (size < 2) {
        return 0;
    }

    // Allocate memory for the table names
    const char *tables[3];
    char table1[256];
    char table2[256];

    // Copy data into the table names, ensuring null termination
    size_t table1_len = (size / 2 < 255) ? size / 2 : 255;
    size_t table2_len = ((size - table1_len) < 255) ? (size - table1_len) : 255;

    memcpy(table1, data, table1_len);
    table1[table1_len] = '\0';

    memcpy(table2, data + table1_len, table2_len);
    table2[table2_len] = '\0';

    // Initialize the tables array with non-null values
    tables[0] = table1;
    tables[1] = table2;
    tables[2] = nullptr; // Null-terminate the array

    // Call the function-under-test
    lou_indexTables(tables);

    return 0;
}