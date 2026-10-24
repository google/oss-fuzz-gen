// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_table at janet.c:33121:13 in janet.h
// janet_cstring at string.c:88:16 in janet.h
// janet_nanbox_from_double at janet.c:37710:7 in janet.h
// janet_table_put at janet.c:33237:6 in janet.h
// janet_cstring at string.c:88:16 in janet.h
// janet_table_get_ex at janet.c:33200:7 in janet.h
// janet_table_remove at janet.c:33222:7 in janet.h
// janet_nanbox_from_pointer at janet.c:37686:7 in janet.h
// janet_table_rawget at janet.c:33212:7 in janet.h
// janet_nanbox_from_double at janet.c:37710:7 in janet.h
// janet_table_put at janet.c:33237:6 in janet.h
// janet_nanbox_to_pointer at janet.c:37680:7 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void initialize_janet() {
    static int initialized = 0;
    if (!initialized) {
        janet_init();
        initialized = 1;
    }
}

static JanetTable *create_dummy_table() {
    JanetTable *table = janet_table(10);
    // Populate with some dummy data
    for (int i = 0; i < 5; i++) {
        char key[10];
        snprintf(key, sizeof(key), "key%d", i);
        janet_table_put(table, janet_wrap_string(janet_cstring(key)), janet_wrap_number(i));
    }
    return table;
}

static Janet create_dummy_janet() {
    return janet_wrap_table(create_dummy_table());
}

int LLVMFuzzerTestOneInput_378(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize Janet environment
    initialize_janet();

    // Create a dummy JanetTable and Janet
    JanetTable *table = create_dummy_table();
    Janet janet = create_dummy_janet();

    // Ensure the input data is null-terminated
    char *null_terminated_data = (char *)malloc(Size + 1);
    if (!null_terminated_data) return 0;
    memcpy(null_terminated_data, Data, Size);
    null_terminated_data[Size] = '\0';

    // Select a key from the input data
    Janet key = janet_wrap_string(janet_cstring(null_terminated_data));

    // Fuzz janet_table_get_ex
    JanetTable *which = NULL;
    Janet result = janet_table_get_ex(table, key, &which);

    // Fuzz janet_table_remove
    result = janet_table_remove(table, key);

    // Fuzz janet_wrap_table
    Janet wrapped_table = janet_wrap_table(table);

    // Fuzz janet_table_rawget
    result = janet_table_rawget(table, key);

    // Fuzz janet_table_put
    janet_table_put(table, key, janet_wrap_number(Size));

    // Fuzz janet_unwrap_table
    JanetTable *unwrapped_table = janet_unwrap_table(wrapped_table);

    // Clean up
    free(null_terminated_data);
    if (unwrapped_table) {
        // Here you would normally free or clean up resources, but Janet's GC will handle it.
    }

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

        LLVMFuzzerTestOneInput_378(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    