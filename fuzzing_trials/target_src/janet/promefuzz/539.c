// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_getstruct at janet.c:4515:1 in janet.h
// janet_nanbox_from_cpointer at janet.c:37698:7 in janet.h
// janet_struct_begin at janet.c:32494:10 in janet.h
// janet_struct_end at janet.c:32603:16 in janet.h
// janet_struct_find at janet.c:32513:16 in janet.h
// janet_optstruct at janet.c:4528:1 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

static void initialize_janet() {
    static int initialized = 0;
    if (!initialized) {
        janet_init();
        initialized = 1;
    }
}

static void fuzz_janet_getstruct(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet) + sizeof(int32_t)) return;

    const Janet *argv = (const Janet *)Data;
    int32_t n = *((int32_t *)(Data + sizeof(Janet)));

    JanetStruct result = janet_getstruct(argv, n);
    (void)result;
}

static void fuzz_janet_wrap_struct(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetKV)) return;

    JanetStruct x = (JanetStruct)Data;
    Janet result = janet_wrap_struct(x);
    (void)result;
}

static void fuzz_janet_struct_begin(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return;

    int32_t count = *((int32_t *)Data);
    JanetKV *result = janet_struct_begin(count);
    if (result) {
        free(result);
    }
}

static void fuzz_janet_struct_end(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetKV)) return;

    JanetKV *st = (JanetKV *)Data;
    JanetStruct result = janet_struct_end(st);
    (void)result;
}

static void fuzz_janet_struct_find(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet) + sizeof(JanetStruct)) return;

    JanetStruct st = (JanetStruct)Data;
    Janet key = *((Janet *)(Data + sizeof(JanetStruct)));

    const JanetKV *result = janet_struct_find(st, key);
    (void)result;
}

static void fuzz_janet_optstruct(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet) + 2 * sizeof(int32_t) + sizeof(JanetStruct)) return;

    const Janet *argv = (const Janet *)Data;
    int32_t argc = *((int32_t *)(Data + sizeof(Janet)));
    int32_t n = *((int32_t *)(Data + sizeof(Janet) + sizeof(int32_t)));
    JanetStruct dflt = *((JanetStruct *)(Data + sizeof(Janet) + 2 * sizeof(int32_t)));

    JanetStruct result = janet_optstruct(argv, argc, n, dflt);
    (void)result;
}

int LLVMFuzzerTestOneInput_539(const uint8_t *Data, size_t Size) {
    initialize_janet();
    fuzz_janet_getstruct(Data, Size);
    fuzz_janet_wrap_struct(Data, Size);
    fuzz_janet_struct_begin(Data, Size);
    fuzz_janet_struct_end(Data, Size);
    fuzz_janet_struct_find(Data, Size);
    fuzz_janet_optstruct(Data, Size);
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

        LLVMFuzzerTestOneInput_539(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    