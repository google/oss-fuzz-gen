// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_table_init_raw at janet.c:33106:13 in janet.h
// janet_table_init_raw at janet.c:33106:13 in janet.h
// janet_dobytes at run.c:31:5 in janet.h
// janet_table_init_raw at janet.c:33106:13 in janet.h
// janet_core_env at janet.c:7992:13 in janet.h
// janet_table_init_raw at janet.c:33106:13 in janet.h
// janet_def at janet.c:34105:6 in janet.h
// janet_table_init_raw at janet.c:33106:13 in janet.h
// janet_core_lookup_table at janet.c:8037:13 in janet.h
// janet_table_init_raw at janet.c:33106:13 in janet.h
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
#include <stdio.h>
#include "janet.h"

#define MAX_CAPACITY 1024

static void fuzz_janet_table_init_raw(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return;
    int32_t capacity = *(int32_t *)Data;
    if (capacity < 0 || capacity > MAX_CAPACITY) return;

    JanetTable table;
    janet_table_init_raw(&table, capacity);
}

static void fuzz_janet_dobytes(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    JanetTable env;
    janet_table_init_raw(&env, 10);

    Janet out;
    janet_dobytes(&env, Data, (int32_t)Size, "./dummy_file", &out);
}

static void fuzz_janet_core_env(const uint8_t *Data, size_t Size) {
    JanetTable replacements;
    janet_table_init_raw(&replacements, 10);

    JanetTable *env = janet_core_env(&replacements);
    (void)env;  // Suppress unused variable warning
}

static void fuzz_janet_def(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    JanetTable env;
    janet_table_init_raw(&env, 10);

    const char *name = "fuzz_var";
    Janet val = {0};  // Assuming a simple Janet value for demonstration
    janet_def(&env, name, val, "Fuzz variable");
}

static void fuzz_janet_core_lookup_table(const uint8_t *Data, size_t Size) {
    JanetTable replacements;
    janet_table_init_raw(&replacements, 10);

    JanetTable *lookup_table = janet_core_lookup_table(&replacements);
    (void)lookup_table;  // Suppress unused variable warning
}

static void fuzz_janet_env_lookup(const uint8_t *Data, size_t Size) {
    JanetTable env;
    janet_table_init_raw(&env, 10);

    JanetTable *new_env = janet_env_lookup(&env);
    (void)new_env;  // Suppress unused variable warning
}

int LLVMFuzzerTestOneInput_725(const uint8_t *Data, size_t Size) {
    janet_init();

    fuzz_janet_table_init_raw(Data, Size);
    fuzz_janet_dobytes(Data, Size);
    fuzz_janet_core_env(Data, Size);
    fuzz_janet_def(Data, Size);
    fuzz_janet_core_lookup_table(Data, Size);
    fuzz_janet_env_lookup(Data, Size);

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

        LLVMFuzzerTestOneInput_725(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    