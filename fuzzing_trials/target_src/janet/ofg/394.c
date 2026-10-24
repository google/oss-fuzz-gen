#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_394(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to extract an int32_t value
    if (size < sizeof(int32_t)) {
        return 0;
    }

    // Initialize a JanetTable
    JanetTable table;
    JanetTable *tablePtr = &table;

    // Extract an int32_t value from the input data
    int32_t capacity = *(int32_t *)data;

    // Ensure capacity is within a reasonable range
    if (capacity < 0) {
        capacity = -capacity; // Make it positive
    }
    if (capacity > 1024) {
        capacity = 1024; // Limit capacity to a maximum value
    }

    // Call the function-under-test
    JanetTable *result = janet_table_init(tablePtr, capacity);

    // Check if the result is not NULL
    if (result == NULL) {
        return 0;
    }

    // Perform additional operations on the JanetTable
    // For example, inserting a key-value pair
    Janet key = janet_wrap_integer(1);
    Janet value = janet_wrap_integer(42);
    janet_table_put(result, key, value);

    // Retrieve the value to ensure the table is functioning
    Janet retrieved = janet_table_get(result, key);
    if (janet_unwrap_integer(retrieved) != 42) {
        abort(); // Trigger an abort if the retrieved value is incorrect
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

    LLVMFuzzerTestOneInput_394(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
