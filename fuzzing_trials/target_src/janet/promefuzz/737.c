// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_dyn at janet.c:4777:7 in janet.h
// janet_resolve_core at janet.c:34455:7 in janet.h
// janet_setdyn at janet.c:4789:6 in janet.h
// janet_table_find at janet.c:33143:10 in janet.h
// janet_var at janet.c:34118:6 in janet.h
// janet_var_sm at janet.c:34110:6 in janet.h
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

static void prepare_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_737(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Initialize Janet VM
    janet_init();

    // Prepare dummy file if needed
    prepare_dummy_file(Data, Size);

    // Create a null-terminated string from the input data
    char name[256];
    size_t name_len = Size < 255 ? Size : 255;
    memcpy(name, Data, name_len);
    name[name_len] = '\0';

    // Create a Janet value from input data
    Janet value;
    value.u64 = 0;
    if (Size >= sizeof(uint64_t)) {
        memcpy(&value.u64, Data, sizeof(uint64_t));
    }

    // Initialize a JanetTable with a small capacity
    JanetTable table;
    table.count = 0;
    table.capacity = 4; // Ensure the table has a small initial capacity
    table.deleted = 0;
    table.data = (JanetKV *)calloc(table.capacity, sizeof(JanetKV));
    table.proto = NULL;

    // Fuzz janet_dyn
    janet_dyn(name);

    // Fuzz janet_resolve_core
    janet_resolve_core(name);

    // Fuzz janet_setdyn
    janet_setdyn(name, value);

    // Fuzz janet_table_find
    janet_table_find(&table, value);

    // Fuzz janet_var
    janet_var(&table, name, value, "documentation");

    // Fuzz janet_var_sm
    janet_var_sm(&table, name, value, "documentation", "source_file", 42);

    // Free allocated memory for the JanetTable
    free(table.data);

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

        LLVMFuzzerTestOneInput_737(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    