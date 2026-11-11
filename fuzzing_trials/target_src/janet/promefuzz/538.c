// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_wrap_true at wrap.c:96:7 in janet.h
// janet_wrap_false at janet.c:37584:7 in janet.h
// janet_wrap_boolean at janet.c:37587:7 in janet.h
// janet_wrap_true at janet.c:37581:7 in janet.h
// janet_wrap_false at wrap.c:99:7 in janet.h
// janet_wrap_boolean at wrap.c:102:7 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_538(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Test janet_wrap_boolean
    int boolean_input = Data[0] % 2; // Only 0 or 1
    Janet result_boolean = janet_wrap_boolean(boolean_input);

    // Test janet_wrap_true
    Janet result_true = janet_wrap_true();

    // Test janet_wrap_false
    Janet result_false = janet_wrap_false();

    // Optionally, inspect the results (e.g., print or verify)
    // In real fuzzing, we typically do not print, but you could log or assert if needed.

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

        LLVMFuzzerTestOneInput_538(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    