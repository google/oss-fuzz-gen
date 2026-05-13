#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

#define MAX_CAPACITY 1024

static JanetTable *create_random_table(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) {
        return NULL;
    }
    int32_t capacity = *(int32_t *)Data % MAX_CAPACITY;
    return janet_table(capacity);
}

static void fuzz_janet_table_merge_table(JanetTable *table, JanetTable *other) {
    janet_table_merge_table(table, other);
}

static void fuzz_janet_table_init(JanetTable *table, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) {
        return;
    }
    int32_t capacity = *(int32_t *)Data % MAX_CAPACITY;
    janet_table_init(table, capacity);
}

static void fuzz_janet_table_init_raw(JanetTable *table, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) {
        return;
    }
    int32_t capacity = *(int32_t *)Data % MAX_CAPACITY;
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of janet_table_init_raw
    janet_table_init_raw(table, JANET_FILE_SERIALIZABLE);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
}

static void fuzz_janet_core_env(const uint8_t *Data, size_t Size) {
    JanetTable *replacements = create_random_table(Data, Size);
    JanetTable *env = janet_core_env(replacements);
    if (replacements) {
        janet_table_merge_table(env, replacements);
    }
}

static void fuzz_janet_env_lookup(JanetTable *env) {
    JanetTable *new_env = janet_env_lookup(env);
    if (new_env) {
        janet_table_merge_table(new_env, env);
    }
}

int LLVMFuzzerTestOneInput_796(const uint8_t *Data, size_t Size) {
    janet_init();

    JanetTable *table1 = create_random_table(Data, Size);
    JanetTable *table2 = create_random_table(Data, Size);

    if (table1 && table2) {
        fuzz_janet_table_merge_table(table1, table2);
        fuzz_janet_table_init(table1, Data, Size);
        fuzz_janet_table_init_raw(table2, Data, Size);
        fuzz_janet_core_env(Data, Size);
        fuzz_janet_env_lookup(table1);
    }

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_796(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
