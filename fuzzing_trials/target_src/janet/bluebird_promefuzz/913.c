#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void initialize_janet_table(JanetTable *table) {
    table->count = 0;
    table->capacity = 0;
    table->deleted = 0;
    table->data = NULL;
    table->proto = NULL;
    // Properly initialize the JanetTable using Janet's API
    janet_table_init(table, 0);
}

static void fuzz_janet_dobytes(JanetTable *env, const uint8_t *Data, size_t Size) {
    Janet out;
    janet_dobytes(env, Data, (int32_t)Size, "./dummy_file", &out);
}

static void fuzz_janet_dostring(JanetTable *env, const uint8_t *Data, size_t Size) {
    char *str = (char *)malloc(Size + 1);
    if (!str) {
        return;
    }
    memcpy(str, Data, Size);
    str[Size] = '\0';
    Janet out;
    janet_dostring(env, str, "./dummy_file", &out);
    free(str);
}

static void fuzz_janet_def_sm(JanetTable *env, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) {
        return;
    }
    Janet val = *(Janet *)(Data);
    janet_def_sm(env, "fuzz_symbol", val, "fuzz documentation", "./dummy_file", 42);
}

static void fuzz_janet_def(JanetTable *env, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) {
        return;
    }
    Janet val = *(Janet *)(Data);
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 3 of janet_def
    janet_def(env, "fuzz_variable", val, NULL);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
}

static void fuzz_janet_env_lookup_into(JanetTable *renv, JanetTable *env) {
    janet_env_lookup_into(renv, env, "prefix_", 1);
}

static void fuzz_janet_var_sm(JanetTable *env, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) {
        return;
    }
    Janet val = *(Janet *)(Data);
    janet_var_sm(env, "fuzz_var", val, "fuzz documentation", "./dummy_file", 42);
}

int LLVMFuzzerTestOneInput_913(const uint8_t *Data, size_t Size) {
    // Initialize the Janet VM before using any Janet functions
    janet_init();

    JanetTable env;
    initialize_janet_table(&env);

    fuzz_janet_dobytes(&env, Data, Size);
    fuzz_janet_dostring(&env, Data, Size);
    fuzz_janet_def_sm(&env, Data, Size);
    fuzz_janet_def(&env, Data, Size);

    JanetTable renv;
    initialize_janet_table(&renv);
    fuzz_janet_env_lookup_into(&renv, &env);

    fuzz_janet_var_sm(&env, Data, Size);

    // Deinitialize the Janet VM after usage
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

    LLVMFuzzerTestOneInput_913(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
