// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
// janet_table_clone at janet.c:33287:13 in janet.h
// janet_table_clear at janet.c:33278:6 in janet.h
// janet_table_weakv at janet.c:33131:13 in janet.h
// janet_table_clear at janet.c:33278:6 in janet.h
// janet_table_deinit at janet.c:33111:6 in janet.h
// janet_table_clear at janet.c:33278:6 in janet.h
// janet_table_deinit at janet.c:33111:6 in janet.h
// janet_clear_memory at gc.c:668:6 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

static JanetTable *create_random_table(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetTable)) return NULL;
    JanetTable *table = malloc(sizeof(JanetTable));
    if (!table) return NULL;
    memcpy(table, Data, sizeof(JanetTable));

    // Ensure capacity is non-negative and reasonable
    table->capacity = table->capacity < 0 ? 0 : table->capacity;

    // Allocate memory for data if capacity is greater than zero
    if (table->capacity > 0) {
        table->data = malloc(sizeof(JanetKV) * table->capacity);
        if (!table->data) {
            free(table);
            return NULL;
        }
        // Initialize data to prevent undefined behavior
        memset(table->data, 0, sizeof(JanetKV) * table->capacity);
    } else {
        table->data = NULL;
    }

    table->proto = NULL;
    return table;
}

int LLVMFuzzerTestOneInput_628(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetTable)) return 0;

    // Initialize Janet VM
    janet_init();

    JanetTable *table = create_random_table(Data, Size);
    if (!table) {
        janet_deinit();
        return 0;
    }

    // Fuzz janet_table_clone
    JanetTable *cloned_table = janet_table_clone(table);
    if (cloned_table) {
        janet_table_clear(cloned_table);
    }

    // Fuzz janet_table_weakv
    int32_t capacity = (int32_t)(Data[0] % 256); // simple capacity choice
    JanetTable *weak_table = janet_table_weakv(capacity);
    if (weak_table) {
        janet_table_clear(weak_table);
        janet_table_deinit(weak_table);
    }

    // Fuzz janet_table_clear
    janet_table_clear(table);

    // Fuzz janet_table_deinit
    janet_table_deinit(table);

    // Fuzz janet_clear_memory
    janet_clear_memory();

    if (table->data) {
        free(table->data);
    }
    free(table);

    // Deinitialize Janet VM
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

        LLVMFuzzerTestOneInput_628(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    