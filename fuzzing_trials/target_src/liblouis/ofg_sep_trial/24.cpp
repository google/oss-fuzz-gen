extern "C" {
    #include <liblouis/liblouis.h>
}

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput_24(const uint8_t *data, size_t size) {
    // Ensure the input data is null-terminated to safely use as a C-string.
    char *tableName = new char[size + 1];
    for (size_t i = 0; i < size; ++i) {
        tableName[i] = static_cast<char>(data[i]);
    }
    tableName[size] = '\0';

    // Call the function-under-test
    const void *result = lou_getTable(tableName);

    // Clean up dynamically allocated memory
    delete[] tableName;

    return 0;
}