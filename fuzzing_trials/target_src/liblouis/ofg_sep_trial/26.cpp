#include <cstdint>
#include <cstdlib>
#include <iostream>

extern "C" {
    // Include the correct header where lou_listTables is declared
    #include "/src/liblouis/liblouis/liblouis.h"
}

// Fuzzer entry point
extern "C" int LLVMFuzzerTestOneInput_26(const uint8_t *data, size_t size) {
    // Call the function-under-test
    char **tables = lou_listTables();

    // Iterate over the list of tables and print them
    if (tables != nullptr) {
        for (int i = 0; tables[i] != nullptr; ++i) {
            std::cout << "Table: " << tables[i] << std::endl;
        }
    }

    // Normally, you would free the memory allocated by lou_listTables if needed
    // but since this is a fuzzer, we assume the environment is reset for each run.

    return 0;
}