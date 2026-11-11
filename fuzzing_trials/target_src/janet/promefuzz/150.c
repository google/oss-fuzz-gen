// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_table_init_raw at janet.c:33106:13 in janet.h
// janet_table_init_raw at janet.c:33106:13 in janet.h
// janet_table_get_ex at janet.c:33200:7 in janet.h
// janet_core_env at janet.c:7992:13 in janet.h
// janet_dobytes at run.c:31:5 in janet.h
// janet_core_env at janet.c:7992:13 in janet.h
// janet_core_lookup_table at janet.c:8037:13 in janet.h
// janet_table_init_raw at janet.c:33106:13 in janet.h
// janet_table_clear at janet.c:33278:6 in janet.h
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
#include <stdlib.h>
#include "janet.h"

#define MAX_CAPACITY 1024

static void fuzz_janet_table_init_raw(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return;
    int32_t capacity = *(int32_t *)Data;
    capacity = capacity < 0 ? 0 : (capacity > MAX_CAPACITY ? MAX_CAPACITY : capacity);

    JanetTable table;
    janet_table_init_raw(&table, capacity);
}

static void fuzz_janet_table_get_ex(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) return;
    Janet key = *(Janet *)Data;

    JanetTable table;
    janet_table_init_raw(&table, 10);
    JanetTable *which = NULL;
    janet_table_get_ex(&table, key, &which);
}

static void fuzz_janet_dobytes(const uint8_t *Data, size_t Size) {
    JanetTable *env = janet_core_env(NULL);
    Janet result;
    janet_dobytes(env, Data, (int32_t)Size, "./dummy_file", &result);
}

static void fuzz_janet_core_env(const uint8_t *Data, size_t Size) {
    JanetTable *replacements = NULL;
    if (Size >= sizeof(JanetTable)) {
        replacements = (JanetTable *)Data;
    }
    janet_core_env(replacements);
}

static void fuzz_janet_core_lookup_table(const uint8_t *Data, size_t Size) {
    JanetTable *replacements = NULL;
    if (Size >= sizeof(JanetTable)) {
        replacements = (JanetTable *)Data;
    }
    janet_core_lookup_table(replacements);
}

static void fuzz_janet_table_clear(const uint8_t *Data, size_t Size) {
    JanetTable table;
    janet_table_init_raw(&table, 10);
    janet_table_clear(&table);
}

int LLVMFuzzerTestOneInput_150(const uint8_t *Data, size_t Size) {
    // Ensure Janet is initialized before calling any Janet functions
    janet_init();

    fuzz_janet_table_init_raw(Data, Size);
    fuzz_janet_table_get_ex(Data, Size);
    fuzz_janet_dobytes(Data, Size);
    fuzz_janet_core_env(Data, Size);
    fuzz_janet_core_lookup_table(Data, Size);
    fuzz_janet_table_clear(Data, Size);

    // Cleanup Janet environment after fuzzing
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

        LLVMFuzzerTestOneInput_150(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    