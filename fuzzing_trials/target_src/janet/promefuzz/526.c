// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_bytes_view at janet.c:34479:5 in janet.h
// janet_nanbox_to_pointer at janet.c:37680:7 in janet.h
// janet_to_string at janet.c:28692:16 in janet.h
// janet_nanbox_from_cpointer at janet.c:37698:7 in janet.h
// janet_description at janet.c:28681:16 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
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

int LLVMFuzzerTestOneInput_526(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) {
        return 0;
    }

    // Initialize Janet VM
    janet_init();

    // Prepare a dummy file if needed
    prepare_dummy_file(Data, Size);

    // Initialize Janet value
    Janet janet_value;
    memcpy(&janet_value, Data, sizeof(Janet));

    // Variables for janet_bytes_view
    const uint8_t *byte_data = NULL;
    int32_t byte_len = 0;

    // Fuzz janet_bytes_view
    janet_bytes_view(janet_value, &byte_data, &byte_len);

    // Fuzz janet_unwrap_string
    JanetString janet_string = janet_unwrap_string(janet_value);

    // Fuzz janet_to_string
    JanetString janet_string_repr = janet_to_string(janet_value);

    // Prepare a symbol for janet_wrap_symbol
    JanetSymbol symbol = (JanetSymbol)Data;
    Janet wrapped_symbol = janet_wrap_symbol(symbol);

    // Fuzz janet_description
    JanetString description = janet_description(janet_value);

    // Clean up Janet VM
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

        LLVMFuzzerTestOneInput_526(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    