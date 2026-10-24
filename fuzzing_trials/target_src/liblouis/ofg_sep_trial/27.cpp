#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

extern "C" {
    // Include the header where lou_listTables is declared
    #include "/src/liblouis/liblouis/liblouis.h"
}

// Fuzzing harness
extern "C" int LLVMFuzzerTestOneInput_27(const uint8_t *data, size_t size) {
    // Call the function-under-test
    char **tables = lou_listTables();

    // Check if the returned pointer is not NULL
    if (tables != NULL) {
        // Iterate through the list of tables and print them
        for (int i = 0; tables[i] != NULL; i++) {
            printf("Table: %s\n", tables[i]);
        }
    }

    return 0;
}