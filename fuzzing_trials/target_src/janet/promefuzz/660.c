// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_table_weakv at janet.c:33131:13 in janet.h
// janet_table_deinit at janet.c:33111:6 in janet.h
// janet_table_weakk at janet.c:33126:13 in janet.h
// janet_table_deinit at janet.c:33111:6 in janet.h
// janet_table_weakkv at janet.c:33136:13 in janet.h
// janet_table_deinit at janet.c:33111:6 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_sweep at gc.c:404:6 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

static void fuzz_janet_table_operations(int32_t capacity) {
    // Create a weak-value table
    JanetTable *table_weakv = janet_table_weakv(capacity);
    if (table_weakv) {
        // Deinitialize the table
        janet_table_deinit(table_weakv);
    }

    // Create a weak-key table
    JanetTable *table_weakk = janet_table_weakk(capacity);
    if (table_weakk) {
        // Deinitialize the table
        janet_table_deinit(table_weakk);
    }

    // Create a weak key-value table
    JanetTable *table_weakkv = janet_table_weakkv(capacity);
    if (table_weakkv) {
        // Deinitialize the table
        janet_table_deinit(table_weakkv);
    }
}

int LLVMFuzzerTestOneInput_660(const uint8_t *Data, size_t Size) {
    // Ensure we have enough data to extract an integer for capacity
    if (Size < sizeof(int32_t)) {
        return 0;
    }

    // Initialize the Janet virtual machine
    janet_init();

    // Extract an integer from the input data for capacity
    int32_t capacity = *(const int32_t *)Data;

    // Perform operations on Janet tables
    fuzz_janet_table_operations(capacity);

    // Perform a sweep of weak references
    janet_sweep();

    // Deinitialize the Janet virtual machine
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

        LLVMFuzzerTestOneInput_660(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    