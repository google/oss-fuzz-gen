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

static Janet generate_random_janet(const uint8_t *data, size_t size) {
    if (size < sizeof(Janet)) return (Janet){.u64 = 0};
    Janet j;
    j.u64 = *((uint64_t *)data);
    return j;
}

static JanetTuple generate_random_tuple(const uint8_t *data, size_t size) {
    return (JanetTuple)data;
}

static JanetStruct generate_random_struct(const uint8_t *data, size_t size) {
    return (JanetStruct)data;
}

int LLVMFuzzerTestOneInput_305(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) return 0;

    JanetTuple random_tuple = generate_random_tuple(Data, Size);
    JanetStruct random_struct = generate_random_struct(Data, Size);
    Janet random_janet = generate_random_janet(Data, Size);

    // Test janet_wrap_tuple
    Janet wrapped_tuple = janet_wrap_tuple(random_tuple);

    // Test janet_wrap_struct
    Janet wrapped_struct = janet_wrap_struct(random_struct);

    // Test janet_unwrap_tuple
    JanetTuple unwrapped_tuple = janet_unwrap_tuple(wrapped_tuple);

    // Test janet_unwrap_abstract
    JanetAbstract unwrapped_abstract = janet_unwrap_abstract(random_janet);

    // Test janet_unwrap_struct
    JanetStruct unwrapped_struct = janet_unwrap_struct(wrapped_struct);

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

        LLVMFuzzerTestOneInput_305(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    