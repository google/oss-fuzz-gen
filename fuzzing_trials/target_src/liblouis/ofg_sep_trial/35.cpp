#include <cstdint>
#include <cstddef>
#include <cstring>

extern "C" {
    // Include the header where lou_checkTable is declared
    int lou_checkTable(const char *);
}

extern "C" int LLVMFuzzerTestOneInput_35(const uint8_t *data, size_t size) {
    // Allocate memory for a null-terminated string
    char *tableName = new char[size + 1];
    
    // Copy the input data into the string and ensure null-termination
    memcpy(tableName, data, size);
    tableName[size] = '\0';

    // Call the function-under-test
    lou_checkTable(tableName);

    // Clean up
    delete[] tableName;

    return 0;
}