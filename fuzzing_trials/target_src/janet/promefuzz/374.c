// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_deinit at vm.c:1732:6 in janet.h
// janet_opttable at janet.c:4539:1 in janet.h
// janet_dostring at run.c:139:5 in janet.h
// janet_nanbox_from_double at janet.c:37710:7 in janet.h
// janet_def_sm at janet.c:34099:6 in janet.h
// janet_put at value.c:764:6 in janet.h
// janet_table_put at janet.c:33237:6 in janet.h
// janet_gettable at janet.c:4514:1 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_table at janet.c:33121:13 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <janet.h>

static JanetTable *create_initialized_table(int32_t capacity) {
    return janet_table(capacity);
}

static void fuzz_janet_opttable(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet) * 2 + sizeof(int32_t) * 2) return;

    const Janet *argv = (const Janet *)Data;
    int32_t argc = (int32_t)(Size / sizeof(Janet));
    int32_t n = (int32_t)argv[argc - 2].i64;
    int32_t dflt_len = (int32_t)argv[argc - 1].i64;

    if (argc > 0) {
        janet_opttable(argv, argc, n, dflt_len);
    }
}

static void fuzz_janet_dostring(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    char *str = (char *)malloc(Size + 1);
    if (!str) return;
    memcpy(str, Data, Size);
    str[Size] = '\0';

    JanetTable *env = create_initialized_table(10);
    if (!env) {
        free(str);
        return;
    }

    Janet out;
    janet_dostring(env, str, "./dummy_file", &out);

    free(str);
}

static void fuzz_janet_def_sm(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    JanetTable *env = create_initialized_table(10);
    if (!env) return;

    char *name = (char *)malloc(Size + 1);
    if (!name) return;
    memcpy(name, Data, Size);
    name[Size] = '\0';

    Janet val = janet_wrap_number((double)Size);
    janet_def_sm(env, name, val, "Fuzzing documentation", "./dummy_file", 42);

    free(name);
}

static void fuzz_janet_put(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet) * 3) return;

    Janet ds = ((Janet *)Data)[0];
    Janet key = ((Janet *)Data)[1];
    Janet value = ((Janet *)Data)[2];

    janet_put(ds, key, value);
}

static void fuzz_janet_table_put(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet) * 2) return;

    JanetTable *t = create_initialized_table(10);
    if (!t) return;

    Janet key = ((Janet *)Data)[0];
    Janet value = ((Janet *)Data)[1];

    janet_table_put(t, key, value);
}

static void fuzz_janet_gettable(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet) * 2) return;

    const Janet *argv = (const Janet *)Data;
    int32_t n = (int32_t)argv[1].i64;

    if (n >= 0 && n < (Size / sizeof(Janet))) {
        janet_gettable(argv, n);
    }
}

int LLVMFuzzerTestOneInput_374(const uint8_t *Data, size_t Size) {
    janet_init();

    fuzz_janet_opttable(Data, Size);
    fuzz_janet_dostring(Data, Size);
    fuzz_janet_def_sm(Data, Size);
    fuzz_janet_put(Data, Size);
    fuzz_janet_table_put(Data, Size);
    fuzz_janet_gettable(Data, Size);

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

        LLVMFuzzerTestOneInput_374(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    