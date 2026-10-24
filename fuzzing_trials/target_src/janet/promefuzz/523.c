// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_scan_uint64 at strtod.c:486:5 in janet.h
// janet_checkuint64 at janet.c:34542:5 in janet.h
// janet_unwrap_u64 at inttypes.c:144:10 in janet.h
// janet_nanbox_from_bits at janet.c:37716:7 in janet.h
// janet_getuinteger64 at janet.c:4675:10 in janet.h
// janet_wrap_u64 at inttypes.c:186:7 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "janet.h"

static void prepare_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_523(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Prepare a dummy file if needed
    prepare_dummy_file(Data, Size);

    // Fuzz janet_scan_uint64
    uint64_t out = 0;
    janet_scan_uint64(Data, (int32_t)Size, &out);

    // Fuzz janet_checkuint64
    Janet janetValue;
    if (Size >= sizeof(uint64_t)) {
        memcpy(&janetValue, Data, sizeof(uint64_t));
        janet_checkuint64(janetValue);
    }

    // Fuzz janet_unwrap_u64
    if (Size >= sizeof(uint64_t)) {
        memcpy(&janetValue, Data, sizeof(uint64_t));
        janet_unwrap_u64(janetValue);
    }

    // Fuzz janet_nanbox_from_bits
    if (Size >= sizeof(uint64_t)) {
        uint64_t bits;
        memcpy(&bits, Data, sizeof(uint64_t));
        janet_nanbox_from_bits(bits);
    }

    // Fuzz janet_getuinteger64
    if (Size >= sizeof(Janet) * 2) {
        Janet argv[2];
        memcpy(argv, Data, sizeof(Janet) * 2);
        janet_getuinteger64(argv, 0);
    }

    // Fuzz janet_wrap_u64
    if (Size >= sizeof(uint64_t)) {
        uint64_t value;
        memcpy(&value, Data, sizeof(uint64_t));
        janet_wrap_u64(value);
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

        LLVMFuzzerTestOneInput_523(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    