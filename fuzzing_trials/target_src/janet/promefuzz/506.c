// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_rng_double at janet.c:20232:8 in janet.h
// janet_rng_longseed at janet.c:20203:6 in janet.h
// janet_rng_seed at janet.c:20193:6 in janet.h
// janet_rng_u32 at janet.c:20217:10 in janet.h
// janet_default_rng at janet.c:20189:11 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "janet.h"

static void fuzz_janet_rng_double(JanetRNG *rng) {
    double result = janet_rng_double(rng);
    (void)result; // Suppress unused variable warning
}

static void fuzz_janet_rng_longseed(JanetRNG *rng, const uint8_t *data, int32_t size) {
    janet_rng_longseed(rng, data, size);
}

static void fuzz_janet_rng_seed(JanetRNG *rng, uint32_t seed) {
    janet_rng_seed(rng, seed);
}

static void fuzz_janet_rng_u32(JanetRNG *rng) {
    uint32_t result = janet_rng_u32(rng);
    (void)result; // Suppress unused variable warning
}

int LLVMFuzzerTestOneInput_506(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) {
        return 0;
    }

    JanetRNG rng;
    uint32_t seed = *(const uint32_t *)Data;
    fuzz_janet_rng_seed(&rng, seed);

    if (Size > sizeof(uint32_t)) {
        fuzz_janet_rng_longseed(&rng, Data + sizeof(uint32_t), (int32_t)(Size - sizeof(uint32_t)));
    }

    fuzz_janet_rng_double(&rng);
    fuzz_janet_rng_u32(&rng);

    JanetRNG *default_rng = janet_default_rng();
    fuzz_janet_rng_double(default_rng);
    fuzz_janet_rng_u32(default_rng);

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

        LLVMFuzzerTestOneInput_506(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    