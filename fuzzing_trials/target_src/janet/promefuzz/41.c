// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
// janet_optinteger64 at janet.c:4862:9 in janet.h
// janet_wrap_s64 at inttypes.c:180:7 in janet.h
// janet_checkint64 at janet.c:34535:5 in janet.h
// janet_unwrap_s64 at inttypes.c:116:9 in janet.h
// janet_getinteger64 at janet.c:4663:9 in janet.h
// janet_getnat at janet.c:4596:9 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "janet.h"

// Helper function to create a dummy Janet array
static void create_dummy_janet_array(Janet *array, size_t size) {
    for (size_t i = 0; i < size; i++) {
        array[i].i64 = (int64_t)i; // Initialize with some integers
    }
}

int LLVMFuzzerTestOneInput_41(const uint8_t *Data, size_t Size) {
    // Ensure we have enough data to work with
    if (Size < sizeof(Janet)) {
        return 0;
    }

    // Initialize the Janet VM
    janet_init();

    // Allocate memory for a dummy Janet array
    size_t array_size = Size / sizeof(Janet);
    Janet *janet_array = (Janet *)malloc(array_size * sizeof(Janet));
    if (!janet_array) {
        janet_deinit();
        return 0;
    }

    // Initialize the array with dummy values
    create_dummy_janet_array(janet_array, array_size);

    // Fuzz janet_optinteger64
    if (array_size > 0) {
        int64_t default_value = 42;
        int64_t result_optinteger64 = janet_optinteger64(janet_array, (int32_t)array_size, 0, default_value);
    }

    // Fuzz janet_wrap_s64
    int64_t sample_value = 123456789;
    Janet wrapped_janet = janet_wrap_s64(sample_value);

    // Fuzz janet_checkint64
    int check_result = janet_checkint64(wrapped_janet);

    // Fuzz janet_unwrap_s64
    if (check_result) {
        int64_t unwrapped_value = janet_unwrap_s64(wrapped_janet);
    }

    // Fuzz janet_getinteger64
    if (array_size > 0) {
        int64_t result_getinteger64 = janet_getinteger64(janet_array, 0);
    }

    // Fuzz janet_getnat
    if (array_size > 0) {
        int32_t result_getnat = janet_getnat(janet_array, 0);
    }

    // Free allocated memory
    free(janet_array);

    // Deinitialize the Janet VM
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

        LLVMFuzzerTestOneInput_41(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    