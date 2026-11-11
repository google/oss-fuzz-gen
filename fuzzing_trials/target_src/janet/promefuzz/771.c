// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_fixarity at janet.c:4447:6 in janet.h
// janet_getnat at janet.c:4596:9 in janet.h
// janet_getinteger64 at janet.c:4663:9 in janet.h
// janet_optcfunction at janet.c:4534:1 in janet.h
// janet_arity at janet.c:4452:6 in janet.h
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

static void fuzz_janet_fixarity(const uint8_t *Data, size_t Size) {
    if (Size < 8) return;
    int32_t arity = *(int32_t *)Data;
    int32_t fix = *(int32_t *)(Data + 4);
    janet_fixarity(arity, fix);
}

static void fuzz_janet_getnat(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet) + 4) return;
    const Janet *argv = (const Janet *)Data;
    int32_t n = *(int32_t *)(Data + sizeof(Janet));
    if (n >= 0 && n < (int32_t)(Size / sizeof(Janet))) {
        janet_getnat(argv, n);
    }
}

static void fuzz_janet_getinteger64(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet) + 4) return;
    const Janet *argv = (const Janet *)Data;
    int32_t n = *(int32_t *)(Data + sizeof(Janet));
    if (n >= 0 && n < (int32_t)(Size / sizeof(Janet))) {
        janet_getinteger64(argv, n);
    }
}

static void fuzz_janet_optcfunction(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet) + 12) return;
    const Janet *argv = (const Janet *)Data;
    int32_t argc = *(int32_t *)(Data + sizeof(Janet));
    int32_t n = *(int32_t *)(Data + sizeof(Janet) + 4);
    JanetCFunction dflt = (JanetCFunction)(*(void **)(Data + sizeof(Janet) + 8));
    if (argc >= 0 && n >= 0 && n < argc && argc <= (int32_t)(Size / sizeof(Janet))) {
        janet_optcfunction(argv, argc, n, dflt);
    }
}

static void fuzz_janet_arity(const uint8_t *Data, size_t Size) {
    if (Size < 12) return;
    int32_t arity = *(int32_t *)Data;
    int32_t min = *(int32_t *)(Data + 4);
    int32_t max = *(int32_t *)(Data + 8);
    janet_arity(arity, min, max);
}

int LLVMFuzzerTestOneInput_771(const uint8_t *Data, size_t Size) {
    fuzz_janet_fixarity(Data, Size);
    fuzz_janet_getnat(Data, Size);
    fuzz_janet_getinteger64(Data, Size);
    fuzz_janet_optcfunction(Data, Size);
    fuzz_janet_arity(Data, Size);
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

        LLVMFuzzerTestOneInput_771(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    