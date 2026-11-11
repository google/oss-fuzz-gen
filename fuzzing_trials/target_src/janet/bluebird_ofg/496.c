#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_496(const uint8_t *data, size_t size) {
    JanetTable *table;
    Janet key;
    Janet value;

    // Initialize the Janet VM
    janet_init();

    // Create a new Janet table
    table = janet_table(10);

    // Ensure there's data to work with
    if (size < sizeof(Janet)) {
        janet_deinit();
        return 0;
    }

    // Use the input data to create a Janet key
    key = janet_wrap_number((double)data[0]);

    // Add a value to the table with the key
    value = janet_wrap_number(42); // Arbitrary value
    janet_table_put(table, key, value);

    // Call the function-under-test
    janet_table_remove(table, key);

    // Clean up the Janet VM
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

    LLVMFuzzerTestOneInput_496(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
