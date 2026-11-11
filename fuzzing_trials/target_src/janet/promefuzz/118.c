// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_nanbox_from_cpointer at janet.c:37698:7 in janet.h
// janet_nanbox_from_cpointer at janet.c:37698:7 in janet.h
// janet_nanbox_to_pointer at janet.c:37680:7 in janet.h
// janet_nanbox_to_pointer at janet.c:37680:7 in janet.h
// janet_nanbox_to_pointer at janet.c:37680:7 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

static void fuzz_janet_wrap_tuple(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetTuple)) return;
    JanetTuple tuple = (JanetTuple)Data;
    Janet wrapped_tuple = janet_wrap_tuple(tuple);
    (void)wrapped_tuple;
}

static void fuzz_janet_wrap_struct(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetStruct)) return;
    JanetStruct jstruct = (JanetStruct)Data;
    Janet wrapped_struct = janet_wrap_struct(jstruct);
    (void)wrapped_struct;
}

static void fuzz_janet_unwrap_tuple(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) return;
    Janet value;
    value.pointer = (void *)Data;
    JanetTuple tuple = janet_unwrap_tuple(value);
    (void)tuple;
}

static void fuzz_janet_unwrap_abstract(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) return;
    Janet value;
    value.pointer = (void *)Data;
    JanetAbstract abstract = janet_unwrap_abstract(value);
    (void)abstract;
}

static void fuzz_janet_unwrap_struct(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) return;
    Janet value;
    value.pointer = (void *)Data;
    JanetStruct jstruct = janet_unwrap_struct(value);
    (void)jstruct;
}

int LLVMFuzzerTestOneInput_118(const uint8_t *Data, size_t Size) {
    fuzz_janet_wrap_tuple(Data, Size);
    fuzz_janet_wrap_struct(Data, Size);
    fuzz_janet_unwrap_tuple(Data, Size);
    fuzz_janet_unwrap_abstract(Data, Size);
    fuzz_janet_unwrap_struct(Data, Size);
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

        LLVMFuzzerTestOneInput_118(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    