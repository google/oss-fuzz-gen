// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_table_init at janet.c:33101:13 in janet.h
// janet_table_clone at janet.c:33287:13 in janet.h
// janet_table_init_raw at janet.c:33106:13 in janet.h
// janet_table_weakv at janet.c:33131:13 in janet.h
// janet_table_weakk at janet.c:33126:13 in janet.h
// janet_table_weakkv at janet.c:33136:13 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

#define MAX_CAPACITY 1024

static void initialize_table(JanetTable *table, int32_t capacity) {
    if (capacity < 0 || capacity > MAX_CAPACITY) {
        capacity = MAX_CAPACITY;
    }
    janet_table_init(table, capacity);
}

static void fuzz_janet_table_functions(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return;

    int32_t capacity;
    memcpy(&capacity, Data, sizeof(int32_t));

    // Ensure capacity is within a valid range
    if (capacity < 0 || capacity > MAX_CAPACITY) {
        capacity = MAX_CAPACITY;
    }

    JanetTable table;
    initialize_table(&table, capacity);

    JanetTable *cloned_table = janet_table_clone(&table);
    (void)cloned_table; // Suppress unused variable warning

    janet_table_init_raw(&table, capacity);

    JanetTable *weakv_table = janet_table_weakv(capacity);
    (void)weakv_table;

    JanetTable *weakk_table = janet_table_weakk(capacity);
    (void)weakk_table;

    JanetTable *weakkv_table = janet_table_weakkv(capacity);
    (void)weakkv_table;
}

int LLVMFuzzerTestOneInput_667(const uint8_t *Data, size_t Size) {
    // Initialize the Janet VM
    janet_init();

    // Fuzz the Janet table functions
    fuzz_janet_table_functions(Data, Size);

    // Deinitialize the Janet VM
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

        LLVMFuzzerTestOneInput_667(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    