// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_getstruct at janet.c:4515:1 in janet.h
// janet_nanbox_from_cpointer at janet.c:37698:7 in janet.h
// janet_struct_rawget at janet.c:32626:7 in janet.h
// janet_struct_find at janet.c:32513:16 in janet.h
// janet_struct_get at janet.c:32632:7 in janet.h
// janet_nanbox_to_pointer at janet.c:37680:7 in janet.h
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

static void initialize_janet_kv(JanetKV *kv, size_t size) {
    for (size_t i = 0; i < size; i++) {
        kv[i].key.u64 = rand();
        kv[i].value.u64 = rand();
    }
}

static JanetStruct create_janet_struct(size_t size) {
    JanetKV *kv = (JanetKV *)malloc(sizeof(JanetKV) * size);
    if (!kv) return NULL;
    initialize_janet_kv(kv, size);
    return kv;
}

static void cleanup_janet_struct(JanetStruct st) {
    free((void *)st);
}

int LLVMFuzzerTestOneInput_381(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t) * 3) return 0;

    int32_t n = *((int32_t *)Data);
    size_t struct_size = *((int32_t *)(Data + sizeof(int32_t))) % 100; // Arbitrary limit

    JanetStruct st = create_janet_struct(struct_size);
    if (!st) return 0;

    // Prepare Janet array
    Janet *argv = (Janet *)malloc(sizeof(Janet) * (n + 1));
    if (!argv) {
        cleanup_janet_struct(st);
        return 0;
    }
    for (int32_t i = 0; i <= n; i++) {
        argv[i].pointer = (i == n) ? (void *)st : NULL;
    }

    // Fuzz janet_getstruct
    if (n >= 0 && n < (int32_t)(Size / sizeof(Janet))) {
        JanetStruct result_st = janet_getstruct(argv, n);
        (void)result_st; // Use the result to prevent unused variable warning
    }

    // Fuzz janet_wrap_struct
    Janet wrapped_value = janet_wrap_struct(st);

    // Fuzz janet_struct_rawget
    if (Size >= sizeof(int32_t) * 3 + sizeof(uint64_t)) {
        Janet key;
        key.u64 = *((uint64_t *)(Data + sizeof(int32_t) * 2));
        Janet rawget_result = janet_struct_rawget(st, key);

        // Fuzz janet_struct_find
        const JanetKV *found_kv = janet_struct_find(st, key);

        // Fuzz janet_struct_get
        Janet get_result = janet_struct_get(st, key);
    }

    // Fuzz janet_unwrap_struct
    JanetStruct unwrapped_st = janet_unwrap_struct(wrapped_value);

    // Cleanup
    cleanup_janet_struct(st);
    free(argv);

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

        LLVMFuzzerTestOneInput_381(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    