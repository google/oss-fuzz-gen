// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_table_clone at janet.c:33287:13 in janet.h
// janet_table_to_struct at janet.c:33323:16 in janet.h
// janet_struct_to_table at janet.c:32655:13 in janet.h
// janet_table_deinit at janet.c:33111:6 in janet.h
// janet_table_find at janet.c:33143:10 in janet.h
// janet_table_merge_struct at janet.c:33318:6 in janet.h
// janet_table_deinit at janet.c:33111:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

static JanetKV *create_dummy_kv_array(int32_t capacity) {
    JanetKV *kv_array = (JanetKV *)malloc(capacity * sizeof(JanetKV));
    if (!kv_array) {
        return NULL;
    }
    for (int32_t i = 0; i < capacity; i++) {
        kv_array[i].key.u64 = (uint64_t)i;
        kv_array[i].value.u64 = (uint64_t)(i * 2);
    }
    return kv_array;
}

static JanetTable *create_dummy_table(int32_t capacity) {
    JanetTable *table = (JanetTable *)malloc(sizeof(JanetTable));
    if (!table) {
        return NULL;
    }
    table->count = capacity;
    table->capacity = capacity;
    table->deleted = 0;
    table->data = create_dummy_kv_array(capacity);
    table->proto = NULL;
    return table;
}

int LLVMFuzzerTestOneInput_640(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return 0;

    int32_t capacity = *((int32_t *)Data);
    Data += sizeof(int32_t);
    Size -= sizeof(int32_t);

    if (capacity <= 0) return 0;

    JanetTable *table = create_dummy_table(capacity);
    if (!table) return 0;

    // Fuzz janet_table_clone
    JanetTable *cloned_table = janet_table_clone(table);
    (void)cloned_table; // Suppress unused variable warning

    // Fuzz janet_table_to_struct
    JanetStruct jstruct = janet_table_to_struct(table);

    // Fuzz janet_struct_to_table
    JanetTable *struct_table = janet_struct_to_table(jstruct);
    if (struct_table) {
        janet_table_deinit(struct_table);
    }

    // Fuzz janet_table_find
    if (Size >= sizeof(Janet)) {
        Janet key;
        memcpy(&key, Data, sizeof(Janet));
        JanetKV *found_kv = janet_table_find(table, key);
        (void)found_kv; // Suppress unused variable warning
    }

    // Fuzz janet_table_merge_struct
    janet_table_merge_struct(table, jstruct);

    // Clean up
    janet_table_deinit(table);
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

        LLVMFuzzerTestOneInput_640(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    