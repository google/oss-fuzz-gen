// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_getsize at janet.c:4687:8 in janet.h
// janet_cryptorand at janet.c:34711:5 in janet.h
// janet_arity at janet.c:4452:6 in janet.h
// janet_rng_longseed at janet.c:20203:6 in janet.h
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

static void fuzz_janet_getsize(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet) + sizeof(int32_t)) return;

    const Janet *argv = (const Janet *)Data;
    int32_t n = *(int32_t *)(Data + sizeof(Janet));

    // Attempt to call janet_getsize
    volatile size_t result;
    result = janet_getsize(argv, n);
}

static void fuzz_janet_cryptorand(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t)) return;

    size_t n = *(size_t *)Data;
    uint8_t *out = (uint8_t *)malloc(n);

    if (out) {
        // Attempt to call janet_cryptorand
        int ret = janet_cryptorand(out, n);
        (void)ret; // Suppress unused variable warning
        free(out);
    }
}

static void fuzz_janet_arity(const uint8_t *Data, size_t Size) {
    if (Size < 3 * sizeof(int32_t)) return;

    int32_t arity = *(int32_t *)Data;
    int32_t min = *(int32_t *)(Data + sizeof(int32_t));
    int32_t max = *(int32_t *)(Data + 2 * sizeof(int32_t));

    // Attempt to call janet_arity
    janet_arity(arity, min, max);
}

static void fuzz_janet_rng_longseed(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetRNG) + sizeof(int32_t)) return;

    JanetRNG rng;
    const uint8_t *bytes = Data;
    int32_t len = *(int32_t *)(Data + Size - sizeof(int32_t));

    // Attempt to call janet_rng_longseed
    janet_rng_longseed(&rng, bytes, len);
}

int LLVMFuzzerTestOneInput_774(const uint8_t *Data, size_t Size) {
    fuzz_janet_getsize(Data, Size);
    fuzz_janet_cryptorand(Data, Size);
    fuzz_janet_arity(Data, Size);
    fuzz_janet_rng_longseed(Data, Size);
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

        LLVMFuzzerTestOneInput_774(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    