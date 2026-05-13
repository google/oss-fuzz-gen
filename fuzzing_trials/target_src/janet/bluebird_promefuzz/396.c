#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static JanetTable *initialize_janet_table() {
    return janet_table(0);
}

static void initialize_janet() {
    static int janet_initialized = 0;
    if (!janet_initialized) {
        janet_init();
        janet_initialized = 1;
    }
}

static void fuzz_janet_dobytes(const uint8_t *Data, size_t Size) {
    JanetTable *env = initialize_janet_table();
    Janet out;
    janet_dobytes(env, Data, (int32_t)Size, "./dummy_file", &out);
}

static void fuzz_janet_var(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t) + 1) {
        return;
    } // Ensure there is enough data for both name and value

    JanetTable *env = initialize_janet_table();
    char *name = malloc(Size + 1);
    memcpy(name, Data, Size);
    name[Size] = '\0'; // Ensure null termination
    Janet val;
    val.u64 = *(const uint64_t *)(Data + 1); // Use part of the data as a value
    janet_var(env, name, val, "Fuzz documentation");
    free(name);
}

static void fuzz_janet_dostring(const uint8_t *Data, size_t Size) {
    JanetTable *env = initialize_janet_table();
    Janet out;
    char *str = malloc(Size + 1);
    memcpy(str, Data, Size);
    str[Size] = '\0'; // Ensure null termination
    const char rxkcqnnl[1024] = "wiwbu";
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of janet_dostring
    janet_dostring(env, rxkcqnnl, "./dummy_file", &out);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
    free(str);
}

static void fuzz_janet_def_sm(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t) + 1) {
        return;
    } // Ensure enough data for name and value

    JanetTable *env = initialize_janet_table();
    char *name = malloc(Size + 1);
    memcpy(name, Data, Size);
    name[Size] = '\0'; // Ensure null termination
    Janet val;
    val.u64 = *(const uint64_t *)(Data + 1);
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function janet_def_sm with janet_var_sm
    janet_var_sm(env, name, val, "Fuzz documentation", "./dummy_file", 42);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR
    free(name);
}

static void fuzz_janet_env_lookup_into(const uint8_t *Data, size_t Size) {
    JanetTable *renv = initialize_janet_table();
    JanetTable *env = initialize_janet_table();
    char *prefix = malloc(Size + 1);
    memcpy(prefix, Data, Size);
    prefix[Size] = '\0'; // Ensure null termination
    int recurse = Size % 2; // Randomly choose recurse based on size
    janet_env_lookup_into(renv, env, prefix, recurse);
    free(prefix);
}

static void fuzz_janet_var_sm(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t) + 1) {
        return;
    } // Ensure enough data for name and value

    JanetTable *env = initialize_janet_table();
    char *name = malloc(Size + 1);
    memcpy(name, Data, Size);
    name[Size] = '\0'; // Ensure null termination
    Janet val;
    val.u64 = *(const uint64_t *)(Data + 1);
    janet_var_sm(env, name, val, "Fuzz documentation", "./dummy_file", 42);
    free(name);
}

int LLVMFuzzerTestOneInput_396(const uint8_t *Data, size_t Size) {
    initialize_janet();
    fuzz_janet_dobytes(Data, Size);
    fuzz_janet_var(Data, Size);
    fuzz_janet_dostring(Data, Size);
    fuzz_janet_def_sm(Data, Size);
    fuzz_janet_env_lookup_into(Data, Size);
    fuzz_janet_var_sm(Data, Size);
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

    LLVMFuzzerTestOneInput_396(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
