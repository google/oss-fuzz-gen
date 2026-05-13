// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_unwrap_u64 at inttypes.c:144:10 in janet.h
// janet_getuinteger64 at janet.c:4675:10 in janet.h
// janet_getsize at janet.c:4687:8 in janet.h
// janet_getnat at janet.c:4596:9 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "janet.h"

static void prepare_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_34(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) {
        return 0;
    }

    // Initialize Janet VM
    janet_init();

    prepare_dummy_file(Data, Size);

    Janet janet_value;
    janet_value.u64 = *((uint64_t *) Data);

    // Fuzz janet_unwrap_u64
    uint64_t result_u64 = 0;
    if (Size > sizeof(Janet)) {
        result_u64 = janet_unwrap_u64(janet_value);
    }

    // Fuzz janet_getuinteger64
    if (Size > sizeof(Janet) + sizeof(int32_t)) {
        int32_t index = *((int32_t *)(Data + sizeof(Janet)));
        Janet *argv = (Janet *)(Data + sizeof(Janet) + sizeof(int32_t));
        result_u64 = janet_getuinteger64(argv, index);
    }

    // Fuzz janet_getsize
    if (Size > sizeof(Janet) + sizeof(int32_t)) {
        int32_t index = *((int32_t *)(Data + sizeof(Janet)));
        Janet *argv = (Janet *)(Data + sizeof(Janet) + sizeof(int32_t));
        size_t result_size = janet_getsize(argv, index);
    }

    // Fuzz janet_getnat
    if (Size > sizeof(Janet) + sizeof(int32_t)) {
        int32_t index = *((int32_t *)(Data + sizeof(Janet)));
        Janet *argv = (Janet *)(Data + sizeof(Janet) + sizeof(int32_t));
        int32_t result_nat = janet_getnat(argv, index);
    }

    // Cleanup Janet VM
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

        LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    