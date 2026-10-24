// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_checkint64 at janet.c:34535:5 in janet.h
// janet_checkuint16 at janet.c:34556:5 in janet.h
// janet_checkint64 at janet.c:34535:5 in janet.h
// janet_checkuint64 at janet.c:34542:5 in janet.h
// janet_checkint16 at janet.c:34549:5 in janet.h
// janet_checkint at janet.c:34521:5 in janet.h
// janet_hash at value.c:309:9 in janet.h
// janet_checkint at janet.c:34521:5 in janet.h
// janet_checkuint64 at janet.c:34542:5 in janet.h
// janet_checkint16 at janet.c:34549:5 in janet.h
// janet_checkuint16 at janet.c:34556:5 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

static void fuzz_janet_checkint64(Janet x) {
    janet_checkint64(x);
}

static void fuzz_janet_hash(Janet x) {
    if (janet_checkint(x) || janet_checkint64(x) || janet_checkuint64(x) || janet_checkint16(x) || janet_checkuint16(x)) {
        janet_hash(x);
    }
}

static void fuzz_janet_checkint(Janet x) {
    janet_checkint(x);
}

static void fuzz_janet_checkuint64(Janet x) {
    janet_checkuint64(x);
}

static void fuzz_janet_checkint16(Janet x) {
    janet_checkint16(x);
}

static void fuzz_janet_checkuint16(Janet x) {
    janet_checkuint16(x);
}

int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) return 0;

    Janet x;
    x.u64 = *((uint64_t *)Data);

    fuzz_janet_checkint64(x);
    fuzz_janet_hash(x);
    fuzz_janet_checkint(x);
    fuzz_janet_checkuint64(x);
    fuzz_janet_checkint16(x);
    fuzz_janet_checkuint16(x);

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

        LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    