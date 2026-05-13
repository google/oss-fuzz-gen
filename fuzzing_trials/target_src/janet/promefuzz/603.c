// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_table_init at janet.c:33101:13 in janet.h
// janet_table_merge_table at janet.c:33313:6 in janet.h
// janet_table_clone at janet.c:33287:13 in janet.h
// janet_table_weakk at janet.c:33126:13 in janet.h
// janet_table_deinit at janet.c:33111:6 in janet.h
// janet_table_clear at janet.c:33278:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "janet.h"

static void initialize_table(JanetTable *table, int32_t capacity) {
    janet_table_init(table, capacity);
}

static void merge_tables(JanetTable *table, JanetTable *other) {
    janet_table_merge_table(table, other);
}

static JanetTable *clone_table(JanetTable *table) {
    return janet_table_clone(table);
}

static JanetTable *create_weak_key_table(int32_t capacity) {
    return janet_table_weakk(capacity);
}

static void deinit_table(JanetTable *table) {
    janet_table_deinit(table);
}

static void clear_table(JanetTable *table) {
    janet_table_clear(table);
}

int LLVMFuzzerTestOneInput_603(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t) * 3) return 0;

    int32_t capacity1 = ((int32_t *)Data)[0];
    int32_t capacity2 = ((int32_t *)Data)[1];
    int32_t capacity3 = ((int32_t *)Data)[2];

    JanetTable table1, table2, table3;
    initialize_table(&table1, capacity1);
    initialize_table(&table2, capacity2);
    initialize_table(&table3, capacity3);

    merge_tables(&table1, &table2);
    merge_tables(&table1, &table3);

    JanetTable *cloned_table = clone_table(&table1);
    if (cloned_table) {
        JanetTable *weak_table = create_weak_key_table(capacity1);
        if (weak_table) {
            merge_tables(weak_table, cloned_table);
            clear_table(weak_table);
            deinit_table(weak_table);
        }
    }

    clear_table(&table1);
    clear_table(&table2);
    clear_table(&table3);

    deinit_table(&table1);
    deinit_table(&table2);
    deinit_table(&table3);

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

        LLVMFuzzerTestOneInput_603(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    