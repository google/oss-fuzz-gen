// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_optnat at janet.c:4850:9 in janet.h
// janet_optnumber at janet.c:4526:1 in janet.h
// janet_getnumber at janet.c:4511:1 in janet.h
// janet_getinteger at janet.c:4630:9 in janet.h
// janet_getnat at janet.c:4596:9 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void initialize_janet() {
    static int initialized = 0;
    if (!initialized) {
        janet_init();
        initialized = 1;
    }
}

static void fuzz_janet_optnat(const Janet *argv, int32_t argc) {
    if (argc > 1) {
        int32_t index = argc > 0 ? (int32_t)(argv[0].i64 % argc) : 0;
        int32_t dflt = (int32_t)(argv[1].i64);
        janet_optnat(argv, argc, index, dflt);
    }
}

static void fuzz_janet_optnumber(const Janet *argv, int32_t argc) {
    if (argc > 1) {
        int32_t index = argc > 0 ? (int32_t)(argv[0].i64 % argc) : 0;
        double dflt = argv[1].number;
        janet_optnumber(argv, argc, index, dflt);
    }
}

static void fuzz_janet_unwrap_integer(const Janet *argv, int32_t argc) {
    if (argc > 0) {
        janet_unwrap_integer(argv[0]);
    }
}

static void fuzz_janet_getnumber(const Janet *argv, int32_t argc) {
    if (argc > 0) {
        int32_t index = (int32_t)(argv[0].i64 % argc);
        janet_getnumber(argv, index);
    }
}

static void fuzz_janet_getinteger(const Janet *argv, int32_t argc) {
    if (argc > 0) {
        int32_t index = (int32_t)(argv[0].i64 % argc);
        janet_getinteger(argv, index);
    }
}

static void fuzz_janet_getnat(const Janet *argv, int32_t argc) {
    if (argc > 0) {
        int32_t index = (int32_t)(argv[0].i64 % argc);
        janet_getnat(argv, index);
    }
}

int LLVMFuzzerTestOneInput_200(const uint8_t *Data, size_t Size) {
    initialize_janet();

    if (Size < sizeof(Janet)) return 0;

    // Calculate number of Janet elements
    int32_t argc = (int32_t)(Size / sizeof(Janet));
    const Janet *argv = (const Janet *)Data;

    fuzz_janet_optnat(argv, argc);
    fuzz_janet_optnumber(argv, argc);
    fuzz_janet_unwrap_integer(argv, argc);
    fuzz_janet_getnumber(argv, argc);
    fuzz_janet_getinteger(argv, argc);
    fuzz_janet_getnat(argv, argc);

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

        LLVMFuzzerTestOneInput_200(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    