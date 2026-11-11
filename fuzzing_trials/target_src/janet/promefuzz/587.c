// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_nanbox_from_cpointer at janet.c:37698:7 in janet.h
// janet_tuple_end at tuple.c:44:14 in janet.h
// janet_gettuple at janet.c:4513:1 in janet.h
// janet_opttuple at janet.c:4527:1 in janet.h
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

static JanetTuple create_dummy_tuple(int32_t length) {
    JanetTupleHead *head = (JanetTupleHead *)malloc(sizeof(JanetTupleHead) + length * sizeof(Janet));
    if (!head) return NULL;
    head->length = length;
    head->hash = 0;
    return (JanetTuple)head->data;
}

static void free_dummy_tuple(JanetTuple tuple) {
    if (tuple) {
        free((void *)((uintptr_t)tuple - offsetof(JanetTupleHead, data)));
    }
}

int LLVMFuzzerTestOneInput_587(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return 0;

    int32_t length = *(int32_t *)Data;
    Data += sizeof(int32_t);
    Size -= sizeof(int32_t);

    JanetTuple tuple = create_dummy_tuple(length);
    if (!tuple) return 0;

    // Fill tuple with dummy data
    for (int32_t i = 0; i < length && Size >= sizeof(Janet); i++) {
        memcpy((void *)&tuple[i], Data, sizeof(Janet));
        Data += sizeof(Janet);
        Size -= sizeof(Janet);
    }

    // Test janet_wrap_tuple
    Janet wrapped = janet_wrap_tuple(tuple);

    // Test janet_tuple_end
    JanetTuple ended = janet_tuple_end((Janet *)tuple);

    // Test janet_gettuple
    if (Size >= sizeof(int32_t)) {
        int32_t index = *(int32_t *)Data;
        Data += sizeof(int32_t);
        Size -= sizeof(int32_t);
        janet_gettuple(&wrapped, index);
    }

    // Test janet_opttuple
    if (Size >= sizeof(int32_t)) {
        int32_t argc = *(int32_t *)Data;
        Data += sizeof(int32_t);
        Size -= sizeof(int32_t);
        if (Size >= argc * sizeof(Janet)) {
            Janet *argv = (Janet *)Data;
            janet_opttuple(argv, argc, 0, tuple);
        }
    }

    // Test janet_unwrap_tuple
    janet_unwrap_tuple(wrapped);

    // Test janet_tuple_head
    if (length > 0) {
        janet_tuple_head(tuple);
    }

    free_dummy_tuple(tuple);
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

        LLVMFuzzerTestOneInput_587(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    