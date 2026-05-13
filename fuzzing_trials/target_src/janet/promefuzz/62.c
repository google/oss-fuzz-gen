// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_checkint at janet.c:34521:5 in janet.h
// janet_checkuint64 at janet.c:34542:5 in janet.h
// janet_checkuint16 at janet.c:34556:5 in janet.h
// janet_hash at value.c:309:9 in janet.h
// janet_checkint at janet.c:34521:5 in janet.h
// janet_checkuint64 at janet.c:34542:5 in janet.h
// janet_checkuint16 at janet.c:34556:5 in janet.h
// janet_nanbox_from_double at janet.c:37710:7 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

// Function to ensure the Janet value is of a hashable type
static int is_hashable_type(Janet x) {
    // Check for valid types (this is a simplified example, adjust based on actual valid types)
    return janet_checkint(x) || janet_checkuint64(x) || janet_checkuint16(x);
}

static void fuzz_janet_hash(Janet x) {
    if (is_hashable_type(x)) {
        int32_t hash = janet_hash(x);
        // Handle the hash value for further validation if needed
        (void)hash;
    }
}

static void fuzz_janet_checkint(Janet x) {
    int is_int = janet_checkint(x);
    // Handle the is_int result for further validation if needed
    (void)is_int;
}

static void fuzz_janet_checkuint64(Janet x) {
    int is_uint64 = janet_checkuint64(x);
    // Handle the is_uint64 result for further validation if needed
    (void)is_uint64;
}

static void fuzz_janet_checkuint16(Janet x) {
    int is_uint16 = janet_checkuint16(x);
    // Handle the is_uint16 result for further validation if needed
    (void)is_uint16;
}

static void fuzz_janet_checktypes(Janet x, int typeflags) {
    int matches_type = janet_checktypes(x, typeflags);
    // Handle the matches_type result for further validation if needed
    (void)matches_type;
}

static void fuzz_janet_wrap_integer(int32_t x) {
    Janet wrapped = janet_wrap_integer(x);
    // Handle the wrapped Janet value for further validation if needed
    (void)wrapped;
}

int LLVMFuzzerTestOneInput_62(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) return 0;

    // Prepare a Janet value from input data
    Janet x;
    x.u64 = *((uint64_t *)Data);

    // Fuzz janet_hash
    fuzz_janet_hash(x);

    // Fuzz janet_checkint
    fuzz_janet_checkint(x);

    // Fuzz janet_checkuint64
    fuzz_janet_checkuint64(x);

    // Fuzz janet_checkuint16
    fuzz_janet_checkuint16(x);

    // Use some part of the data as typeflags for janet_checktypes
    if (Size >= sizeof(Janet) + sizeof(int)) {
        int typeflags = *((int *)(Data + sizeof(Janet)));
        fuzz_janet_checktypes(x, typeflags);
    }

    // Use some part of the data as integer for janet_wrap_integer
    if (Size >= sizeof(Janet) + sizeof(int32_t)) {
        int32_t int_value = *((int32_t *)(Data + sizeof(Janet)));
        fuzz_janet_wrap_integer(int_value);
    }

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

        LLVMFuzzerTestOneInput_62(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    