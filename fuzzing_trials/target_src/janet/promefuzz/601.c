// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_nanbox_from_pointer at janet.c:37686:7 in janet.h
// janet_nanbox_from_pointer at janet.c:37686:7 in janet.h
// janet_nanbox_to_pointer at janet.c:37680:7 in janet.h
// janet_nanbox_from_cpointer at janet.c:37698:7 in janet.h
// janet_nanbox_to_pointer at janet.c:37680:7 in janet.h
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

static void fuzz_janet_wrap_pointer(void *data) {
    Janet result = janet_wrap_pointer(data);
    (void)result; // Suppress unused variable warning
}

static void fuzz_janet_nanbox_from_pointer(void *data, uint64_t tagmask) {
    Janet result = janet_nanbox_from_pointer(data, tagmask);
    (void)result; // Suppress unused variable warning
}

static void fuzz_janet_nanbox_to_pointer(Janet janet_value) {
    void *result = janet_nanbox_to_pointer(janet_value);
    (void)result; // Suppress unused variable warning
}

static void fuzz_janet_nanbox_from_cpointer(const void *data, uint64_t tagmask) {
    Janet result = janet_nanbox_from_cpointer(data, tagmask);
    (void)result; // Suppress unused variable warning
}

static void fuzz_janet_unwrap_pointer(Janet janet_value) {
    void *result = janet_unwrap_pointer(janet_value);
    (void)result; // Suppress unused variable warning
}

int LLVMFuzzerTestOneInput_601(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(void *)) return 0;

    // Prepare a dummy pointer from input data
    void *dummy_pointer = (void *)Data;

    // Fuzz janet_wrap_pointer
    fuzz_janet_wrap_pointer(dummy_pointer);

    // Prepare a tagmask
    if (Size < sizeof(void *) + sizeof(uint64_t)) return 0;
    uint64_t tagmask = *(uint64_t *)(Data + sizeof(void *));

    // Fuzz janet_nanbox_from_pointer
    fuzz_janet_nanbox_from_pointer(dummy_pointer, tagmask);

    // Prepare a Janet value
    Janet janet_value;
    if (Size < sizeof(Janet)) return 0;
    janet_value.u64 = *(uint64_t *)Data;

    // Fuzz janet_nanbox_to_pointer
    fuzz_janet_nanbox_to_pointer(janet_value);

    // Fuzz janet_nanbox_from_cpointer
    fuzz_janet_nanbox_from_cpointer(dummy_pointer, tagmask);

    // Fuzz janet_unwrap_pointer
    fuzz_janet_unwrap_pointer(janet_value);

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

        LLVMFuzzerTestOneInput_601(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    