// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_var at janet.c:34118:6 in janet.h
// janet_var_sm at janet.c:34110:6 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_resolve_core at janet.c:34455:7 in janet.h
// janet_setdyn at janet.c:4789:6 in janet.h
// janet_def_sm at janet.c:34099:6 in janet.h
// janet_def at janet.c:34105:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "janet.h"

static void initialize_janet_vm() {
    static int initialized = 0;
    if (!initialized) {
        janet_init();
        initialized = 1;
    }
}

static void fuzz_janet_resolve_core(const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        char *name = (char *)malloc(Size + 1);
        if (name) {
            memcpy(name, Data, Size);
            name[Size] = '\0';
            Janet result = janet_resolve_core(name);
            (void)result; // Use the result if needed
            free(name);
        }
    }
}

static void fuzz_janet_setdyn(const uint8_t *Data, size_t Size) {
    if (Size > sizeof(Janet)) {
        char *name = (char *)malloc(Size - sizeof(Janet) + 1);
        if (name) {
            memcpy(name, Data, Size - sizeof(Janet));
            name[Size - sizeof(Janet)] = '\0';
            Janet value;
            memcpy(&value, Data + Size - sizeof(Janet), sizeof(Janet));
            janet_setdyn(name, value);
            free(name);
        }
    }
}

static void fuzz_janet_def_sm(const uint8_t *Data, size_t Size) {
    if (Size > sizeof(Janet) + 8) {
        JanetTable env;
        memset(&env, 0, sizeof(JanetTable));
        env.data = (JanetKV *)malloc(sizeof(JanetKV) * 8);
        env.capacity = 8;
        env.count = 0;
        env.deleted = 0;

        char *name = (char *)malloc(Size - sizeof(Janet) - 8 + 1);
        if (name) {
            memcpy(name, Data, Size - sizeof(Janet) - 8);
            name[Size - sizeof(Janet) - 8] = '\0';
            Janet val;
            memcpy(&val, Data + Size - sizeof(Janet) - 8, sizeof(Janet));
            janet_def_sm(&env, name, val, "doc", "source_file", 42);
            free(name);
        }
        free(env.data);
    }
}

static void fuzz_janet_def(const uint8_t *Data, size_t Size) {
    if (Size > sizeof(Janet) + 4) {
        JanetTable env;
        memset(&env, 0, sizeof(JanetTable));
        env.data = (JanetKV *)malloc(sizeof(JanetKV) * 8);
        env.capacity = 8;
        env.count = 0;
        env.deleted = 0;

        char *name = (char *)malloc(Size - sizeof(Janet) - 4 + 1);
        if (name) {
            memcpy(name, Data, Size - sizeof(Janet) - 4);
            name[Size - sizeof(Janet) - 4] = '\0';
            Janet val;
            memcpy(&val, Data + Size - sizeof(Janet) - 4, sizeof(Janet));
            janet_def(&env, name, val, "doc");
            free(name);
        }
        free(env.data);
    }
}

static void fuzz_janet_var(const uint8_t *Data, size_t Size) {
    if (Size > sizeof(Janet) + 4) {
        JanetTable env;
        memset(&env, 0, sizeof(JanetTable));
        env.data = (JanetKV *)malloc(sizeof(JanetKV) * 8);
        env.capacity = 8;
        env.count = 0;
        env.deleted = 0;

        char *name = (char *)malloc(Size - sizeof(Janet) - 4 + 1);
        if (name) {
            memcpy(name, Data, Size - sizeof(Janet) - 4);
            name[Size - sizeof(Janet) - 4] = '\0';
            Janet val;
            memcpy(&val, Data + Size - sizeof(Janet) - 4, sizeof(Janet));
            janet_var(&env, name, val, "doc");
            free(name);
        }
        free(env.data);
    }
}

static void fuzz_janet_var_sm(const uint8_t *Data, size_t Size) {
    if (Size > sizeof(Janet) + 8) {
        JanetTable env;
        memset(&env, 0, sizeof(JanetTable));
        env.data = (JanetKV *)malloc(sizeof(JanetKV) * 8);
        env.capacity = 8;
        env.count = 0;
        env.deleted = 0;

        char *name = (char *)malloc(Size - sizeof(Janet) - 8 + 1);
        if (name) {
            memcpy(name, Data, Size - sizeof(Janet) - 8);
            name[Size - sizeof(Janet) - 8] = '\0';
            Janet val;
            memcpy(&val, Data + Size - sizeof(Janet) - 8, sizeof(Janet));
            janet_var_sm(&env, name, val, "doc", "source_file", 42);
            free(name);
        }
        free(env.data);
    }
}

int LLVMFuzzerTestOneInput_666(const uint8_t *Data, size_t Size) {
    initialize_janet_vm();
    fuzz_janet_resolve_core(Data, Size);
    fuzz_janet_setdyn(Data, Size);
    fuzz_janet_def_sm(Data, Size);
    fuzz_janet_def(Data, Size);
    fuzz_janet_var(Data, Size);
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

        if(size < 1 + 1)
            exit(0);

        data = (uint8_t *)malloc((size_t)size);
        if(data == NULL)
            exit(0);

        if(fread(data, (size_t)size, 1, f) != 1)
            exit(0);

        LLVMFuzzerTestOneInput_666(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    