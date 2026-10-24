#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_343(const uint8_t *data, size_t size) {
    // Initialize the Janet environment
    janet_init();

    JanetTable *table = janet_table(10); // Create a JanetTable with an initial capacity
    Janet key, value;

    // Ensure there is at least enough data for a key-value pair
    if (size < 2 * sizeof(Janet)) {
        janet_deinit(); // Clean up the Janet environment
        return 0;
    }

    // Initialize a key and value from the input data
    key = janet_wrap_integer((int32_t)data[0]);
    value = janet_wrap_integer((int32_t)data[1]);

    // Insert the key-value pair into the table
    janet_table_put(table, key, value);

    // Retrieve the value using the key
    Janet result = janet_table_rawget(table, key);

    // Clean up
    // Remove the janet_table_deinit call as janet_table_put does not allocate memory
    // that needs to be manually freed, and janet_table_deinit is not a valid function.
    // The Janet library manages memory for tables automatically.
    // janet_table_deinit(table); // This line is incorrect and should be removed.
    
    janet_deinit(); // Clean up the Janet environment

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

    LLVMFuzzerTestOneInput_343(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
