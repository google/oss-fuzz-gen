// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_table at janet.c:33121:13 in janet.h
// janet_string at string.c:49:16 in janet.h
// janet_nanbox_from_bits at janet.c:37716:7 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_nanbox_from_double at janet.c:37710:7 in janet.h
// janet_table_put at janet.c:33237:6 in janet.h
// janet_table_get_ex at janet.c:33200:7 in janet.h
// janet_table_get at janet.c:33179:7 in janet.h
// janet_nanbox_from_pointer at janet.c:37686:7 in janet.h
// janet_nanbox_to_pointer at janet.c:37680:7 in janet.h
// janet_table_rawget at janet.c:33212:7 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "janet.h"

static JanetTable *create_dummy_table() {
    JanetTable *table = janet_table(10);
    return table;
}

static Janet create_dummy_key(const uint8_t *Data, size_t Size) {
    Janet key;
    if (Size > 0) {
        key = janet_wrap_string(janet_string(Data, Size));
    } else {
        key = janet_wrap_nil();
    }
    return key;
}

int LLVMFuzzerTestOneInput_146(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    janet_init();

    JanetTable *table = create_dummy_table();
    Janet key = create_dummy_key(Data, Size);
    Janet value = janet_wrap_number((double)Size);

    // Fuzz janet_table_put
    janet_table_put(table, key, value);

    // Fuzz janet_table_get_ex
    JanetTable *which = NULL;
    Janet ret_ex = janet_table_get_ex(table, key, &which);

    // Fuzz janet_table_get
    Janet ret_get = janet_table_get(table, key);

    // Fuzz janet_wrap_table
    Janet wrapped_table = janet_wrap_table(table);

    // Fuzz janet_unwrap_table
    JanetTable *unwrapped_table = janet_unwrap_table(wrapped_table);

    // Fuzz janet_table_rawget
    if (unwrapped_table) {
        Janet ret_rawget = janet_table_rawget(unwrapped_table, key);
    }

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

        LLVMFuzzerTestOneInput_146(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    