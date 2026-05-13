// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_nanbox_from_double at janet.c:37710:7 in janet.h
// janet_nanbox_from_double at janet.c:37710:7 in janet.h
// janet_table_put at janet.c:33237:6 in janet.h
// janet_cstring at string.c:88:16 in janet.h
// janet_symbol at janet.c:32957:16 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_nanbox_from_double at janet.c:37710:7 in janet.h
// janet_resolve at janet.c:34444:18 in janet.h
// janet_table_get_ex at janet.c:33200:7 in janet.h
// janet_table_get at janet.c:33179:7 in janet.h
// janet_table_rawget at janet.c:33212:7 in janet.h
// janet_nanbox_from_pointer at janet.c:37686:7 in janet.h
// janet_nanbox_from_double at janet.c:37710:7 in janet.h
// janet_table_put at janet.c:33237:6 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
// janet_table at janet.c:33121:13 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static JanetTable *create_dummy_table() {
    JanetTable *table = janet_table(10);
    if (table) {
        for (int i = 0; i < 5; i++) {
            Janet key = janet_wrap_integer(i);
            Janet value = janet_wrap_integer(i * 10);
            janet_table_put(table, key, value);
        }
    }
    return table;
}

static JanetSymbol create_dummy_symbol(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return janet_cstring("default");
    }
    char buffer[256];
    size_t copy_size = Size < 255 ? Size : 255;
    memcpy(buffer, Data, copy_size);
    buffer[copy_size] = '\0';
    return janet_symbol(buffer, copy_size);
}

int LLVMFuzzerTestOneInput_317(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize the Janet environment
    janet_init();

    JanetTable *env = create_dummy_table();
    Janet result;
    JanetTable *which = NULL;

    // Create a valid symbol from input data
    JanetSymbol sym = create_dummy_symbol(Data, Size);

    // Create a valid key from input data
    Janet key = janet_wrap_integer(Data[0]);

    // Fuzz janet_resolve
    janet_resolve(env, sym, &result);

    // Fuzz janet_table_get_ex
    janet_table_get_ex(env, key, &which);

    // Fuzz janet_table_get
    janet_table_get(env, key);

    // Fuzz janet_table_rawget
    janet_table_rawget(env, key);

    // Fuzz janet_wrap_table
    Janet wrapped_table = janet_wrap_table(env);

    // Fuzz janet_table_put
    if (Size > 1) {
        Janet value = janet_wrap_integer(Data[1]);
        janet_table_put(env, key, value);
    }

    // Cleanup the Janet environment
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

        LLVMFuzzerTestOneInput_317(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    