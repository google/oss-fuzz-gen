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
#include "janet.h"

static void fuzz_janet_wrap_pointer(const uint8_t *Data, size_t Size) {
    if (Size >= sizeof(void *)) {
        void *ptr = *(void **)Data;
        Janet wrapped = janet_wrap_pointer(ptr);
        (void)wrapped; // Use wrapped to avoid unused variable warnings
    }
}

static void fuzz_janet_nanbox_from_pointer(const uint8_t *Data, size_t Size) {
    if (Size >= sizeof(void *) + sizeof(uint64_t)) {
        void *ptr = *(void **)Data;
        uint64_t tagmask = *(uint64_t *)(Data + sizeof(void *));
        Janet boxed = janet_nanbox_from_pointer(ptr, tagmask);
        (void)boxed; // Use boxed to avoid unused variable warnings
    }
}

static void fuzz_janet_nanbox_to_pointer(const uint8_t *Data, size_t Size) {
    if (Size >= sizeof(Janet)) {
        Janet x = *(Janet *)Data;
        void *ptr = janet_nanbox_to_pointer(x);
        (void)ptr; // Use ptr to avoid unused variable warnings
    }
}

static void fuzz_janet_nanbox_from_cpointer(const uint8_t *Data, size_t Size) {
    if (Size >= sizeof(void *) + sizeof(uint64_t)) {
        const void *ptr = *(const void **)Data;
        uint64_t tagmask = *(uint64_t *)(Data + sizeof(void *));
        Janet boxed = janet_nanbox_from_cpointer(ptr, tagmask);
        (void)boxed; // Use boxed to avoid unused variable warnings
    }
}

static void fuzz_janet_unwrap_pointer(const uint8_t *Data, size_t Size) {
    if (Size >= sizeof(Janet)) {
        Janet x = *(Janet *)Data;
        void *ptr = janet_unwrap_pointer(x);
        (void)ptr; // Use ptr to avoid unused variable warnings
    }
}

int LLVMFuzzerTestOneInput_780(const uint8_t *Data, size_t Size) {
    fuzz_janet_wrap_pointer(Data, Size);
    fuzz_janet_nanbox_from_pointer(Data, Size);
    fuzz_janet_nanbox_to_pointer(Data, Size);
    fuzz_janet_nanbox_from_cpointer(Data, Size);
    fuzz_janet_unwrap_pointer(Data, Size);
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

        LLVMFuzzerTestOneInput_780(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    