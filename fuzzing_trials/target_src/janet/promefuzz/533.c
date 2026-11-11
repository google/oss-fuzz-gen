// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_table_get_ex at janet.c:33200:7 in janet.h
// janet_table_remove at janet.c:33222:7 in janet.h
// janet_table_get at janet.c:33179:7 in janet.h
// janet_table_rawget at janet.c:33212:7 in janet.h
// janet_nanbox_from_pointer at janet.c:37686:7 in janet.h
// janet_nanbox_to_pointer at janet.c:37680:7 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static JanetTable *create_dummy_table() {
    JanetTable *table = (JanetTable *)malloc(sizeof(JanetTable));
    if (!table) return NULL;
    table->count = 0;
    table->capacity = 8;
    table->deleted = 0;
    table->data = (JanetKV *)calloc(table->capacity, sizeof(JanetKV));
    table->proto = NULL;
    return table;
}

static void destroy_dummy_table(JanetTable *table) {
    if (table) {
        free(table->data);
        free(table);
    }
}

static Janet create_valid_janet_key(const uint8_t *Data, size_t Size) {
    Janet key;
    if (Size >= sizeof(void *)) {
        key.pointer = (void *)Data; // Use data as pointer
    } else {
        key.u64 = 0; // Default value if insufficient data
    }
    return key;
}

int LLVMFuzzerTestOneInput_533(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) return 0;

    // Create a dummy JanetTable
    JanetTable *table = create_dummy_table();
    if (!table) return 0;

    // Create a valid Janet key from input data
    Janet key = create_valid_janet_key(Data, Size);

    // Prepare a dummy table pointer for janet_table_get_ex
    JanetTable *which = NULL;

    // Fuzz janet_table_get_ex
    janet_table_get_ex(table, key, &which);

    // Fuzz janet_table_remove
    janet_table_remove(table, key);

    // Fuzz janet_table_get
    janet_table_get(table, key);

    // Fuzz janet_table_rawget
    janet_table_rawget(table, key);

    // Fuzz janet_wrap_table
    Janet wrapped = janet_wrap_table(table);

    // Fuzz janet_unwrap_table
    JanetTable *unwrapped = janet_unwrap_table(wrapped);

    // Clean up
    destroy_dummy_table(table);

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

        LLVMFuzzerTestOneInput_533(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    