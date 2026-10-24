// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_bytes_view at janet.c:34479:5 in janet.h
// janet_string_begin at string.c:34:10 in janet.h
// janet_to_string at janet.c:28692:16 in janet.h
// janet_string at string.c:49:16 in janet.h
// janet_string_begin at string.c:34:10 in janet.h
// janet_string_end at string.c:43:16 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

static void initialize_janet_vm() {
    static int initialized = 0;
    if (!initialized) {
        janet_init();
        initialized = 1;
    }
}

static void fuzz_janet_bytes_view(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) return;

    Janet janet_value;
    memcpy(&janet_value, Data, sizeof(Janet));

    const uint8_t *byte_data = NULL;
    int32_t length = 0;
    janet_bytes_view(janet_value, &byte_data, &length);
}

static void fuzz_janet_string_begin(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return;

    int32_t length;
    memcpy(&length, Data, sizeof(int32_t));

    uint8_t *str = janet_string_begin(length);
    // Since we can't free memory manually, we don't need to do anything else
}

static void fuzz_janet_to_string(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) return;

    Janet janet_value;
    memcpy(&janet_value, Data, sizeof(Janet));

    janet_to_string(janet_value);
}

static void fuzz_janet_string(const uint8_t *Data, size_t Size) {
    if (Size == 0) return;

    int32_t length = (int32_t)(Size > INT32_MAX ? INT32_MAX : Size);
    janet_string(Data, length);
}

static void fuzz_janet_string_end(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return;

    int32_t length;
    memcpy(&length, Data, sizeof(int32_t));

    if (length < 0) return;

    uint8_t *str = janet_string_begin(length);
    if (!str) return;

    janet_string_end(str);
}

int LLVMFuzzerTestOneInput_766(const uint8_t *Data, size_t Size) {
    initialize_janet_vm();
    fuzz_janet_bytes_view(Data, Size);
    fuzz_janet_string_begin(Data, Size);
    fuzz_janet_to_string(Data, Size);
    fuzz_janet_string(Data, Size);
    fuzz_janet_string_end(Data, Size);
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

        LLVMFuzzerTestOneInput_766(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    