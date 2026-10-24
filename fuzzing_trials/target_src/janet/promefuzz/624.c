// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_table_merge_table at janet.c:33313:6 in janet.h
// janet_table_clone at janet.c:33287:13 in janet.h
// janet_table_init at janet.c:33101:13 in janet.h
// janet_table_init_raw at janet.c:33106:13 in janet.h
// janet_table_weakv at janet.c:33131:13 in janet.h
// janet_env_lookup at marsh.c:130:13 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

#define MAX_CAPACITY 1024

static void fuzz_janet_table_merge_table(JanetTable *table, JanetTable *other) {
    janet_table_merge_table(table, other);
}

static void fuzz_janet_table_clone(JanetTable *table) {
    JanetTable *clone = janet_table_clone(table);
    // Do not manually free the clone, let the garbage collector handle it
    (void)clone;
}

static void fuzz_janet_table_init(JanetTable *table, int32_t capacity) {
    janet_table_init(table, capacity);
}

static void fuzz_janet_table_init_raw(JanetTable *table, int32_t capacity) {
    janet_table_init_raw(table, capacity);
}

static void fuzz_janet_table_weakv(int32_t capacity) {
    JanetTable *weakv_table = janet_table_weakv(capacity);
    // Let the garbage collector manage the weakv_table
    (void)weakv_table;
}

static void fuzz_janet_env_lookup(JanetTable *env) {
    JanetTable *env_lookup = janet_env_lookup(env);
    // Let the garbage collector manage the env_lookup
    (void)env_lookup;
}

int LLVMFuzzerTestOneInput_624(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t) * 2) return 0;

    int32_t capacity1, capacity2;
    memcpy(&capacity1, Data, sizeof(int32_t));
    memcpy(&capacity2, Data + sizeof(int32_t), sizeof(int32_t));

    capacity1 = capacity1 % MAX_CAPACITY;
    capacity2 = capacity2 % MAX_CAPACITY;

    JanetTable table1, table2, table3, table4, env;

    // Initialize Janet VM
    janet_init();

    fuzz_janet_table_init(&table1, capacity1);
    fuzz_janet_table_init(&table2, capacity2);
    fuzz_janet_table_merge_table(&table1, &table2);

    fuzz_janet_table_clone(&table1);
    fuzz_janet_table_init_raw(&table3, capacity1);
    fuzz_janet_table_init_raw(&table4, capacity2);

    fuzz_janet_table_weakv(capacity1);
    fuzz_janet_env_lookup(&env);

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

        LLVMFuzzerTestOneInput_624(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    