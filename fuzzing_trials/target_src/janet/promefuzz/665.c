// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_dictionary_view at janet.c:34506:5 in janet.h
// janet_sorted_keys at janet.c:34589:9 in janet.h
// janet_dictionary_next at janet.c:34030:16 in janet.h
// janet_dictionary_next at janet.c:34030:16 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static Janet create_random_janet(uint8_t type) {
    Janet janet;
    switch (type % 4) {
        case 0:
            janet.i64 = (int64_t) rand();
            break;
        case 1:
            janet.u64 = (uint64_t) rand();
            break;
        case 2:
            janet.number = (double) rand() / RAND_MAX;
            break;
        case 3:
            janet.pointer = NULL; // Simplified for fuzzing
            break;
    }
    return janet;
}

static void fuzz_janet_dictionary_view(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) return;

    Janet tab = create_random_janet(Data[0]);
    const JanetKV *data = NULL;
    int32_t len = 0, cap = 0;

    janet_dictionary_view(tab, &data, &len, &cap);
}

static void fuzz_janet_sorted_keys(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetKV)) return;

    int32_t cap = (int32_t)(Size / sizeof(JanetKV));

    if (cap <= 0) return; // Ensure cap is positive

    int32_t *index_buffer = (int32_t *) malloc(cap * sizeof(int32_t));
    if (!index_buffer) return;

    // Ensure the Data buffer is large enough to be treated as an array of JanetKV
    if (Size >= sizeof(JanetKV) * cap) {
        // Properly initialize the JanetKV array
        JanetKV *dict = (JanetKV *) malloc(cap * sizeof(JanetKV));
        if (!dict) {
            free(index_buffer);
            return;
        }
        memcpy(dict, Data, cap * sizeof(JanetKV));

        // Validate the dict before calling the function
        for (int32_t i = 0; i < cap; i++) {
            dict[i].key = create_random_janet(Data[i % Size]);
            dict[i].value = create_random_janet(Data[(i + 1) % Size]);
        }
        
        janet_sorted_keys(dict, cap, index_buffer);

        free(dict);
    }

    free(index_buffer);
}

static void fuzz_janet_dictionary_next(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetKV)) return;

    int32_t cap = (int32_t)(Size / sizeof(JanetKV));

    if (cap <= 0) return; // Ensure cap is positive

    const JanetKV *kvs = (const JanetKV *)Data;
    const JanetKV *kv = NULL;

    // Ensure the Data buffer is large enough to be treated as an array of JanetKV
    if (Size >= sizeof(JanetKV) * cap) {
        const JanetKV *result = janet_dictionary_next(kvs, cap, kv);
        if (result) {
            // Optionally, iterate further
            while ((result = janet_dictionary_next(kvs, cap, result)) != NULL) {}
        }
    }
}

int LLVMFuzzerTestOneInput_665(const uint8_t *Data, size_t Size) {
    fuzz_janet_dictionary_view(Data, Size);
    fuzz_janet_sorted_keys(Data, Size);
    fuzz_janet_dictionary_next(Data, Size);

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

        LLVMFuzzerTestOneInput_665(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    