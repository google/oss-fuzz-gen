// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_table_init at janet.c:33101:13 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_table_merge_table at janet.c:33313:6 in janet.h
// janet_table_clone at janet.c:33287:13 in janet.h
// janet_table_weakv at janet.c:33131:13 in janet.h
// janet_env_lookup at marsh.c:130:13 in janet.h
// janet_table at janet.c:33121:13 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

static void initialize_dummy_table(JanetTable *table, int32_t capacity) {
    if (capacity < 0) capacity = 0; // Ensure capacity is non-negative
    janet_table_init(table, capacity);
    // Optionally populate the table with dummy data if needed
}

int LLVMFuzzerTestOneInput_443(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return 0;

    int32_t capacity = *((int32_t *)Data);
    JanetTable table1, table2, *clonedTable, *weakTable, *envTable, *newTable;

    // Initialize the Janet environment
    janet_init();

    // Initialize tables with safe capacity
    initialize_dummy_table(&table1, capacity);
    initialize_dummy_table(&table2, capacity);

    // Test janet_table_merge_table
    janet_table_merge_table(&table1, &table2);

    // Test janet_table_clone
    clonedTable = janet_table_clone(&table1);

    // Test janet_table_weakv
    weakTable = janet_table_weakv(capacity);

    // Test janet_env_lookup
    envTable = janet_env_lookup(&table1);

    // Test janet_table
    newTable = janet_table(capacity);

    // Clean up and finalize the Janet environment
    janet_deinit();

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

        if(size < 1 + 1)
            exit(0);

        data = (uint8_t *)malloc((size_t)size);
        if(data == NULL)
            exit(0);

        if(fread(data, (size_t)size, 1, f) != 1)
            exit(0);

        LLVMFuzzerTestOneInput_443(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    