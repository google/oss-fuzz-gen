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

static Janet generate_random_janet(const uint8_t *Data, size_t Size) {
    Janet janet;
    if (Size < sizeof(uint64_t)) {
        janet.u64 = 0;
    } else {
        memcpy(&janet.u64, Data, sizeof(uint64_t));
    }
    return janet;
}

int LLVMFuzzerTestOneInput_701(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetKV) * 10) {
        return 0;
    }

    // Prepare dummy Janet table or struct
    JanetKV *dummy_kvs = (JanetKV *)malloc(sizeof(JanetKV) * 10);
    if (!dummy_kvs) {
        return 0;
    }

    for (int i = 0; i < 10; i++) {
        dummy_kvs[i].key = generate_random_janet(Data, Size);
        dummy_kvs[i].value = generate_random_janet(Data, Size);
    }

    Janet dummy_janet;
    dummy_janet.pointer = dummy_kvs;

    // Call janet_dictionary_view
    const JanetKV *data = NULL;
    int32_t len = 0;
    int32_t cap = 0;
    janet_dictionary_view(dummy_janet, &data, &len, &cap);

    // Prepare index buffer for janet_sorted_keys
    int32_t cap_buffer = 10;
    int32_t *index_buffer = (int32_t *)malloc(sizeof(int32_t) * cap_buffer);
    if (index_buffer) {
        if (Size >= sizeof(JanetKV) * cap_buffer) {
            janet_sorted_keys(data, len, index_buffer);
        }
        free(index_buffer);
    }

    // Call janet_dictionary_next
    const JanetKV *next_kv = NULL;
    next_kv = janet_dictionary_next(data, len, NULL);

    while (next_kv) {
        next_kv = janet_dictionary_next(data, len, next_kv);
    }

    // Cleanup
    free(dummy_kvs);
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

        LLVMFuzzerTestOneInput_701(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    