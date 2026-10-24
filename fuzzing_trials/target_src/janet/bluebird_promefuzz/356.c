#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static JanetTable *initialize_janet_table() {
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of janet_table
    JanetTable *env = janet_table(JANET_SANDBOX_UNMARSHAL);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
    return env;
}

static void fuzz_janet_dobytes(JanetTable *env, const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        Janet out;
        janet_dobytes(env, Data, (int32_t)Size, "./dummy_file", &out);
    }
}

static void fuzz_janet_dostring(JanetTable *env, const uint8_t *Data, size_t Size) {
    if (Size > 0) {
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
}

static void fuzz_janet_def(JanetTable *env, const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        char *name = (char *)malloc(Size + 1);
        if (!name) {
                return;
        }
        memcpy(name, Data, Size);
        name[Size] = '\0';
        Janet val = janet_wrap_number((double)Size);
        janet_def(env, name, val, "documentation");
        free(name);
    }
}

static void fuzz_janet_var(JanetTable *env, const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        char *name = (char *)malloc(Size + 1);
        if (!name) {
                return;
        }
        memcpy(name, Data, Size);
        name[Size] = '\0';
        Janet val = janet_wrap_number((double)Size);
        janet_var(env, name, val, "documentation");
        free(name);
    }
}

static void fuzz_janet_def_sm(JanetTable *env, const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        char *name = (char *)malloc(Size + 1);
        if (!name) {
                return;
        }
        memcpy(name, Data, Size);
        name[Size] = '\0';
        Janet val = janet_wrap_number((double)Size);
        janet_def_sm(env, name, val, "documentation", "./dummy_file", 42);
        free(name);
    }
}

static void fuzz_janet_var_sm(JanetTable *env, const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        char *name = (char *)malloc(Size + 1);
        if (!name) {
                return;
        }
        memcpy(name, Data, Size);
        name[Size] = '\0';
        Janet val = janet_wrap_number((double)Size);
        janet_var_sm(env, name, val, "documentation", "./dummy_file", 42);
        free(name);
    }
}

int LLVMFuzzerTestOneInput_356(const uint8_t *Data, size_t Size) {
    janet_init();
    JanetTable *env = initialize_janet_table();

    fuzz_janet_dobytes(env, Data, Size);
    fuzz_janet_dostring(env, Data, Size);
    fuzz_janet_def(env, Data, Size);
    fuzz_janet_var(env, Data, Size);
    fuzz_janet_def_sm(env, Data, Size);
    fuzz_janet_var_sm(env, Data, Size);

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

    LLVMFuzzerTestOneInput_356(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
