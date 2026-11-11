#include <stdint.h>
#include <stdlib.h>
#include <janet.h>

extern int32_t janet_length(Janet);

int LLVMFuzzerTestOneInput_154(const uint8_t *data, size_t size) {
    Janet janet_value;
    JanetArray *array;
    JanetTable *table;
    JanetString string;

    if (size == 0) {
        return 0;
    }

    // Initialize Janet VM
    janet_init();

    // Create different types of Janet values to test janet_length function
    array = janet_array(size);
    table = janet_table(size);
    string = janet_string(data, size);

    // Populate array with some values
    for (size_t i = 0; i < size; i++) {
        janet_array_push(array, janet_wrap_integer((int32_t)data[i]));
    }

    // Populate table with some key-value pairs
    for (size_t i = 0; i < size; i++) {
        janet_table_put(table, janet_wrap_integer((int32_t)i), janet_wrap_integer((int32_t)data[i]));
    }

    // Test janet_length with different types
    janet_value = janet_wrap_array(array);
    janet_length(janet_value);

    janet_value = janet_wrap_table(table);
    janet_length(janet_value);

    janet_value = janet_wrap_string(string);
    janet_length(janet_value);

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_154(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
