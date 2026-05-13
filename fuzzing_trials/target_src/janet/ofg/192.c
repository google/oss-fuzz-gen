#include <stdint.h>
#include <stddef.h>
#include <janet.h>

// Define the LLVMFuzzerTestOneInput function
int LLVMFuzzerTestOneInput_192(const uint8_t *data, size_t size) {
    // Ensure there is enough data to create three Janet objects
    if (size < 3) {
        return 0;
    }

    // Initialize Janet VM
    janet_init();

    // Create three Janet objects from the input data
    Janet key = janet_wrap_integer(data[0]);
    Janet value = janet_wrap_integer(data[1]);
    JanetTable *table_ptr = janet_table(10); // Create a table with an initial capacity
    Janet table = janet_wrap_table(table_ptr); // Wrap the table pointer into a Janet object

    // Call the function-under-test
    janet_put(table, key, value); // Use the wrapped table object instead of the pointer

    // Clean up Janet VM
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

    LLVMFuzzerTestOneInput_192(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
