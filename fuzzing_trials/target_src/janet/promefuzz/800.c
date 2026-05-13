// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_dictionary_get at janet.c:34021:7 in janet.h
// janet_table_init at janet.c:33101:13 in janet.h
// janet_dictionary_next at janet.c:34030:16 in janet.h
// janet_table_get_ex at janet.c:33200:7 in janet.h
// janet_dictionary_view at janet.c:34506:5 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

static Janet random_janet_key(const uint8_t *Data, size_t Size) {
    Janet key;
    if (Size < sizeof(uint64_t)) {
        key.u64 = 0;
    } else {
        memcpy(&key.u64, Data, sizeof(uint64_t));
    }
    return key;
}

static void fuzz_janet_dictionary_get(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetKV)) return;

    JanetKV kv;
    memcpy(&kv, Data, sizeof(JanetKV));

    int32_t cap = Size / sizeof(JanetKV);
    Janet key = random_janet_key(Data + sizeof(JanetKV), Size - sizeof(JanetKV));

    janet_dictionary_get(&kv, cap, key);
}

static void fuzz_janet_table_init(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return;

    int32_t capacity;
    memcpy(&capacity, Data, sizeof(int32_t));

    JanetTable table;
    janet_table_init(&table, capacity);
}

static void fuzz_janet_dictionary_next(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetKV)) return;

    JanetKV kv;
    memcpy(&kv, Data, sizeof(JanetKV));

    int32_t cap = Size / sizeof(JanetKV);
    janet_dictionary_next(&kv, cap, NULL);
}

static void fuzz_janet_table_get_ex(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetTable) + sizeof(Janet)) return;

    JanetTable table;
    memcpy(&table, Data, sizeof(JanetTable));

    Janet key = random_janet_key(Data + sizeof(JanetTable), Size - sizeof(JanetTable));
    JanetTable *which;

    janet_table_get_ex(&table, key, &which);
}

static void fuzz_janet_dictionary_view(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) return;

    Janet tab;
    memcpy(&tab, Data, sizeof(Janet));

    const JanetKV *data;
    int32_t len, cap;
    janet_dictionary_view(tab, &data, &len, &cap);
}

int LLVMFuzzerTestOneInput_800(const uint8_t *Data, size_t Size) {
    fuzz_janet_dictionary_get(Data, Size);
    fuzz_janet_table_init(Data, Size);
    fuzz_janet_dictionary_next(Data, Size);
    fuzz_janet_table_get_ex(Data, Size);
    fuzz_janet_dictionary_view(Data, Size);

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

        LLVMFuzzerTestOneInput_800(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    