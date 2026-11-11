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
#include "janet.h"

static Janet random_janet_value(const uint8_t *Data, size_t Size) {
    Janet value;
    if (Size < sizeof(Janet)) {
        value.u64 = 0;
    } else {
        memcpy(&value, Data, sizeof(Janet));
    }
    return value;
}

static void initialize_janet_table(JanetTable *table) {
    table->count = 0;
    table->capacity = 8; // Set a default capacity
    table->deleted = 0;
    table->data = (JanetKV *)calloc(table->capacity, sizeof(JanetKV));
    table->proto = NULL;
}

int LLVMFuzzerTestOneInput_172(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize Janet VM
    janet_init();

    // Prepare a null-terminated string from the input data
    char variable_name[256];
    size_t name_length = Size < 255 ? Size : 255;
    memcpy(variable_name, Data, name_length);
    variable_name[name_length] = '\0';

    // Fuzz janet_dyn
    Janet dyn_result = janet_dyn(variable_name);

    // Fuzz janet_resolve_core
    Janet core_result = janet_resolve_core(variable_name);

    // Generate a random Janet value for setting dynamic variables
    Janet random_value = random_janet_value(Data, Size);

    // Fuzz janet_setdyn
    janet_setdyn(variable_name, random_value);

    // Prepare a JanetTable
    JanetTable table;
    initialize_janet_table(&table);

    // Fuzz janet_table_find
    JanetKV *kv_result = janet_table_find(&table, random_value);

    // Fuzz janet_var
    janet_var(&table, variable_name, random_value, "Fuzz documentation");

    // Fuzz janet_var_sm
    janet_var_sm(&table, variable_name, random_value, "Fuzz documentation", "fuzz_source.c", 42);

    // Free allocated memory for the table
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

        LLVMFuzzerTestOneInput_172(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    