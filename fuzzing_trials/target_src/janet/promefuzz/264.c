// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_nanbox_from_double at janet.c:37710:7 in janet.h
// janet_array at janet.c:1562:13 in janet.h
// janet_nanbox_from_pointer at janet.c:37686:7 in janet.h
// janet_putindex at value.c:718:6 in janet.h
// janet_checkint at janet.c:34521:5 in janet.h
// janet_tuple_begin at tuple.c:34:8 in janet.h
// janet_checkuint16 at janet.c:34556:5 in janet.h
// janet_nanbox_from_double at janet.c:37710:7 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void fuzz_janet_putindex(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t) * 2) return;

    int32_t index = *((int32_t *)Data);
    int32_t value_int = *((int32_t *)(Data + sizeof(int32_t)));
    Janet value = janet_wrap_integer(value_int);
    
    // Create a simple Janet array for testing
    JanetArray *array = janet_array(1);
    janet_putindex(janet_wrap_array(array), index, value);
}

static void fuzz_janet_checkint(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int64_t)) return;

    Janet x;
    x.i64 = *((int64_t *)Data);

    (void)janet_checkint(x);
}

static void fuzz_janet_tuple_begin(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return;

    int32_t length = *((int32_t *)Data);

    if (length < 0 || length > 1024) return; // Limit to a reasonable length
    Janet *tuple = janet_tuple_begin(length);
    (void)tuple; // Suppress unused variable warning
}

static void fuzz_janet_checkuint16(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int64_t)) return;

    Janet x;
    x.i64 = *((int64_t *)Data);

    (void)janet_checkuint16(x);
}

static void fuzz_janet_wrap_integer(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return;

    int32_t x = *((int32_t *)Data);

    (void)janet_wrap_integer(x);
}

int LLVMFuzzerTestOneInput_264(const uint8_t *Data, size_t Size) {
    janet_init();

    fuzz_janet_putindex(Data, Size);
    fuzz_janet_checkint(Data, Size);
    fuzz_janet_tuple_begin(Data, Size);
    fuzz_janet_checkuint16(Data, Size);
    fuzz_janet_wrap_integer(Data, Size);

    janet_deinit();
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

        LLVMFuzzerTestOneInput_264(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    