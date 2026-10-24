// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_nanbox_from_bits at janet.c:37716:7 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_table_init at janet.c:33101:13 in janet.h
// janet_nanbox_from_pointer at janet.c:37686:7 in janet.h
// janet_nanbox_from_pointer at janet.c:37686:7 in janet.h
// janet_nanbox_from_pointer at janet.c:37686:7 in janet.h
// janet_getcfunction at janet.c:4522:1 in janet.h
// janet_getfunction at janet.c:4521:1 in janet.h
// janet_dostring at run.c:139:5 in janet.h
// janet_register at janet.c:34286:6 in janet.h
// janet_nanbox_from_pointer at janet.c:37686:7 in janet.h
// janet_optcfunction at janet.c:4534:1 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <janet.h>

static Janet dummy_cfunction(int32_t argc, Janet *argv) {
    // A dummy C function for testing
    (void) argc;
    (void) argv;
    return janet_wrap_nil();
}

int LLVMFuzzerTestOneInput_783(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize Janet VM
    janet_init();

    // Prepare dummy JanetTable environment
    JanetTable env;
    janet_table_init(&env, 0);

    // Prepare dummy Janet values array
    Janet argv[3];
    argv[0] = janet_wrap_cfunction(dummy_cfunction);
    argv[1] = janet_wrap_cfunction(dummy_cfunction);
    argv[2] = janet_wrap_cfunction(dummy_cfunction);

    // Select an index within bounds for janet_getcfunction and janet_getfunction
    int32_t index = Data[0] % 3;

    // Fuzz janet_getcfunction
    JanetCFunction cfunc = NULL;
    if (janet_checktype(argv[index], JANET_FUNCTION)) {
        cfunc = janet_getcfunction(argv, index);
    }

    // Fuzz janet_getfunction
    JanetFunction *func = NULL;
    if (janet_checktype(argv[index], JANET_FUNCTION)) {
        func = janet_getfunction(argv, index);
    }

    // Write dummy Janet code to a file
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }

    // Fuzz janet_dostring
    Janet out;
    if (Size > 0 && Data[Size - 1] == '\0') {
        janet_dostring(&env, (const char *)Data, "fuzz_source", &out);
    }

    // Fuzz janet_register
    janet_register("dummy_name", dummy_cfunction);

    // Fuzz janet_wrap_cfunction
    Janet wrapped = janet_wrap_cfunction(dummy_cfunction);

    // Fuzz janet_optcfunction
    JanetCFunction opt_cfunc = janet_optcfunction(argv, 3, index, dummy_cfunction);

    // Cleanup
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

        LLVMFuzzerTestOneInput_783(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    