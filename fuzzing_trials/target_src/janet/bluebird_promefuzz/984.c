#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static JanetTable *initialize_env() {
    JanetTable *env = janet_table(0);
    return env;
}

static void fuzz_janet_dobytes(JanetTable *env, const uint8_t *Data, size_t Size) {
    Janet out;
    const char *sourcePath = "./dummy_file";
    int result = janet_dobytes(env, Data, (int32_t)Size, sourcePath, &out);
    if (result != 0) {
        // Handle error
    }
}

static void fuzz_janet_var(JanetTable *env, const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return;
    }
    const char *name = "fuzz_var";
    Janet val;
    val.u64 = Data[0]; // Use first byte for simplicity
    const char *documentation = "Fuzz variable";
    janet_var(env, name, val, documentation);
}

static void fuzz_janet_dostring(JanetTable *env, const uint8_t *Data, size_t Size) {
    char *str = (char *)malloc(Size + 1);
    if (!str) {
        return;
    }
    memcpy(str, Data, Size);
    str[Size] = '\0';
    Janet out;
    const char *sourcePath = "./dummy_file";
    int result = janet_dostring(env, str, sourcePath, &out);
    free(str);
    if (result != 0) {
        // Handle error
    }
}

static void fuzz_janet_def_sm(JanetTable *env, const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return;
    }
    const char *name = "fuzz_symbol";
    Janet val;
    val.u64 = Data[0]; // Use first byte for simplicity
    const char *documentation = "Fuzz symbol";
    const char *source_file = "./dummy_file";
    int32_t source_line = 1;
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function janet_def_sm with janet_var_sm
    janet_var_sm(env, name, val, documentation, source_file, source_line);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR
}

static void fuzz_janet_env_lookup_into(JanetTable *env, const uint8_t *Data, size_t Size) {
    JanetTable *renv = janet_table(0);
    const char *prefix = "fuzz_";
    int recurse = 1;
    janet_env_lookup_into(renv, env, prefix, recurse);
}

static void fuzz_janet_var_sm(JanetTable *env, const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return;
    }
    const char *name = "fuzz_var_sm";
    Janet val;
    val.u64 = Data[0]; // Use first byte for simplicity
    const char *documentation = "Fuzz variable with metadata";
    const char *source_file = "./dummy_file";
    int32_t source_line = 1;
    janet_var_sm(env, name, val, documentation, source_file, source_line);
}

int LLVMFuzzerTestOneInput_984(const uint8_t *Data, size_t Size) {
    // Initialize Janet VM
    janet_init();

    JanetTable *env = initialize_env();

    fuzz_janet_dobytes(env, Data, Size);
    fuzz_janet_var(env, Data, Size);
    fuzz_janet_dostring(env, Data, Size);
    fuzz_janet_def_sm(env, Data, Size);
    fuzz_janet_env_lookup_into(env, Data, Size);
    fuzz_janet_var_sm(env, Data, Size);

    // Cleanup Janet VM
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

    LLVMFuzzerTestOneInput_984(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
