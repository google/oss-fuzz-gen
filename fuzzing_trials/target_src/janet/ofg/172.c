#include <stdint.h>
#include <string.h>
#include <janet.h>

// Ensure to include the Janet header for proper function declarations

int LLVMFuzzerTestOneInput_172(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to extract a 32-bit integer
    if (size < sizeof(int32_t)) {
        return 0;
    }

    // Extract an int32_t value from the input data
    int32_t capacity;
    memcpy(&capacity, data, sizeof(int32_t));

    // Ensure capacity is a positive value and within a reasonable range
    if (capacity <= 0 || capacity > 1000) { // Assuming 1000 as a reasonable upper limit
        return 0;
    }

    // Call the function-under-test
    JanetTable *table = janet_table_weakv(capacity);

    // Optionally, perform operations on the table to further test its behavior
    if (table) {
        // Example operation: insert a dummy key-value pair
        Janet key = janet_wrap_integer(1);
        Janet value = janet_wrap_integer(42);
        janet_table_put(table, key, value);

        // Clean up the table if necessary
        janet_table_deinit(table);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_172(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
