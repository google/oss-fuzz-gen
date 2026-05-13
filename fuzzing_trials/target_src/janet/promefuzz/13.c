// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_nanbox_to_pointer at janet.c:37680:7 in janet.h
// janet_nanbox_from_bits at janet.c:37716:7 in janet.h
// janet_getcfunction at janet.c:4522:1 in janet.h
// janet_register at janet.c:34286:6 in janet.h
// janet_nanbox_from_pointer at janet.c:37686:7 in janet.h
// janet_optcfunction at janet.c:4534:1 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
// janet_nanbox_from_bits at janet.c:37716:7 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static Janet dummy_cfunction(int32_t argc, Janet *argv) {
    return janet_wrap_nil();
}

int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) return 0;

    janet_init();

    // Prepare a dummy Janet value
    Janet x;
    memcpy(&x, Data, sizeof(Janet));

    // Fuzz janet_unwrap_cfunction
    JanetCFunction cfun = janet_unwrap_cfunction(x);

    // Prepare an array of Janet values
    const int32_t max_argv_size = 10;
    Janet argv[max_argv_size];
    for (int i = 0; i < max_argv_size; i++) {
        if (Size >= sizeof(Janet) * (i + 1)) {
            memcpy(&argv[i], Data + sizeof(Janet) * i, sizeof(Janet));
        } else {
            argv[i] = janet_wrap_nil(); // Default to nil if not enough data
        }
    }

    // Fuzz janet_getcfunction
    int32_t n = (int32_t)(Data[0] % max_argv_size);
    if (n >= 0 && n < max_argv_size) {
        JanetCFunction cfun2 = janet_getcfunction(argv, n);
    }

    // Prepare a name for janet_register
    const char *name = "dummy_function";

    // Fuzz janet_register
    janet_register(name, dummy_cfunction);

    // Fuzz janet_wrap_cfunction
    Janet wrapped_cfun = janet_wrap_cfunction(dummy_cfunction);

    // Fuzz janet_optcfunction
    int32_t argc = max_argv_size;
    JanetCFunction dflt = dummy_cfunction;
    JanetCFunction opt_cfun = janet_optcfunction(argv, argc, n, dflt);

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

        LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    