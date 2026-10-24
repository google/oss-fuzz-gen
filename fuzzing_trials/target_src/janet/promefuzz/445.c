// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_resolve_core at janet.c:34455:7 in janet.h
// janet_compile at compile.c:1199:20 in janet.h
// janet_nanbox_to_pointer at janet.c:37680:7 in janet.h
// janet_nanbox_to_pointer at janet.c:37680:7 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void initialize_janet() {
    static int initialized = 0;
    if (!initialized) {
        janet_init();
        initialized = 1;
    }
}

static void fuzz_janet_resolve_core(const uint8_t *Data, size_t Size) {
    char *name = malloc(Size + 1);
    if (name) {
        memcpy(name, Data, Size);
        name[Size] = '\0';
        janet_resolve_core(name);
        free(name);
    }
}

static void fuzz_janet_compile(const uint8_t *Data, size_t Size) {
    JanetTable env;
    memset(&env, 0, sizeof(JanetTable)); // Ensure the table is properly zero-initialized
    env.data = malloc(10 * sizeof(JanetKV)); // Arbitrary size for demonstration
    env.capacity = 10;

    if (env.data) {
        memset(env.data, 0, 10 * sizeof(JanetKV)); // Ensure the data array is zero-initialized
        Janet source;
        source.pointer = (void *)Data;

        JanetString where = (JanetString)"dummy_location";
        janet_compile(source, &env, where);

        free(env.data);
    }
}

static void fuzz_janet_unwrap_string(const uint8_t *Data, size_t Size) {
    if (Size >= sizeof(Janet)) {
        Janet x;
        memcpy(&x, Data, sizeof(Janet));
        janet_unwrap_string(x);
    }
}

static void fuzz_janet_unwrap_symbol(const uint8_t *Data, size_t Size) {
    if (Size >= sizeof(Janet)) {
        Janet x;
        memcpy(&x, Data, sizeof(Janet));
        janet_unwrap_symbol(x);
    }
}

int LLVMFuzzerTestOneInput_445(const uint8_t *Data, size_t Size) {
    initialize_janet();
    fuzz_janet_resolve_core(Data, Size);
    fuzz_janet_compile(Data, Size);
    fuzz_janet_unwrap_string(Data, Size);
    fuzz_janet_unwrap_symbol(Data, Size);
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

        LLVMFuzzerTestOneInput_445(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    