// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_string_begin at string.c:34:10 in janet.h
// janet_symbol at janet.c:32957:16 in janet.h
// janet_to_string at janet.c:28692:16 in janet.h
// janet_getstring at janet.c:4516:1 in janet.h
// janet_string at string.c:49:16 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_314(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize Janet VM
    janet_init();

    // Fuzz janet_string_begin
    int32_t length = Data[0];
    uint8_t *str_begin = janet_string_begin(length);

    // Fuzz janet_symbol
    if (Size > 1) {
        int32_t sym_len = (Size - 1) > INT32_MAX ? INT32_MAX : (Size - 1);
        JanetSymbol symbol = janet_symbol(Data + 1, sym_len);
    }

    // Fuzz janet_to_string
    if (Size >= sizeof(Janet)) {
        Janet x;
        memcpy(&x, Data, sizeof(Janet));

        // Check if the Janet type is valid for conversion
        if (janet_checktype(x, JANET_STRING) || 
            janet_checktype(x, JANET_SYMBOL) || 
            janet_checktype(x, JANET_KEYWORD) || 
            janet_checktype(x, JANET_BUFFER) || 
            janet_checktype(x, JANET_ABSTRACT)) {
            JanetString str = janet_to_string(x);
        }
    }

    // Fuzz janet_getstring
    if (Size >= sizeof(Janet) * 2) {
        Janet argv[2];
        memcpy(argv, Data, sizeof(Janet) * 2);
        int32_t index = Data[Size - 1] % 2; // Ensure index is within bounds

        // Ensure the type is a string before calling janet_getstring
        if (janet_checktype(argv[index], JANET_STRING)) {
            JanetString get_str = janet_getstring(argv, index);
        }
    }

    // Fuzz janet_string
    if (Size > 1) {
        int32_t buf_len = (Size - 1) > INT32_MAX ? INT32_MAX : (Size - 1);
        JanetString new_str = janet_string(Data + 1, buf_len);
    }

    // Clean up
    write_dummy_file(Data, Size);

    // Deinitialize Janet VM
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

        LLVMFuzzerTestOneInput_314(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    