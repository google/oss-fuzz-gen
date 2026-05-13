// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_nanbox_from_pointer at janet.c:37686:7 in janet.h
// janet_nanbox_to_pointer at janet.c:37680:7 in janet.h
// janet_nanbox_from_bits at janet.c:37716:7 in janet.h
// janet_wrap_u64 at inttypes.c:186:7 in janet.h
// janet_nanbox_from_cpointer at janet.c:37698:7 in janet.h
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

static int janet_initialized = 0;

static void initialize_janet() {
    if (!janet_initialized) {
        janet_init();
        janet_initialized = 1;
    }
}

static void fuzz_janet_nanbox_from_pointer(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(void *) + sizeof(uint64_t)) return;
    void *p = (void *)(Data);
    uint64_t tagmask = *(uint64_t *)(Data + sizeof(void *));
    Janet result = janet_nanbox_from_pointer(p, tagmask);
    (void)result;
}

static void fuzz_janet_nanbox_to_pointer(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) return;
    Janet x;
    memcpy(&x, Data, sizeof(Janet));
    void *result = janet_nanbox_to_pointer(x);
    (void)result;
}

static void fuzz_janet_nanbox_from_bits(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t)) return;
    uint64_t bits = *(uint64_t *)Data;
    Janet result = janet_nanbox_from_bits(bits);
    (void)result;
}

static void fuzz_janet_wrap_u64(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t)) return;
    uint64_t x = *(uint64_t *)Data;
    Janet result = janet_wrap_u64(x);
    (void)result;
}

static void fuzz_janet_nanbox_from_cpointer(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(void *) + sizeof(uint64_t)) return;
    const void *p = (const void *)(Data);
    uint64_t tagmask = *(uint64_t *)(Data + sizeof(void *));
    Janet result = janet_nanbox_from_cpointer(p, tagmask);
    (void)result;
}

int LLVMFuzzerTestOneInput_730(const uint8_t *Data, size_t Size) {
    initialize_janet();
    fuzz_janet_nanbox_from_pointer(Data, Size);
    fuzz_janet_nanbox_to_pointer(Data, Size);
    fuzz_janet_nanbox_from_bits(Data, Size);
    fuzz_janet_wrap_u64(Data, Size);
    fuzz_janet_nanbox_from_cpointer(Data, Size);
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

        LLVMFuzzerTestOneInput_730(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    