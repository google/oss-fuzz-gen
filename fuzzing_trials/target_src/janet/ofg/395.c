#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <janet.h>
#include <string.h>

int LLVMFuzzerTestOneInput_395(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for an int32_t and at least one key-value pair
    if (size < sizeof(int32_t) + 2) {
        return 0;
    }

    // Initialize the Janet environment
    janet_init();

    // Initialize a JanetTable object
    JanetTable table;

    // Extract an int32_t from the input data
    int32_t hint = *((int32_t *)data);
    data += sizeof(int32_t);
    size -= sizeof(int32_t);

    // Call the function-under-test
    JanetTable *result = janet_table_init(&table, hint);

    // Check if the table was initialized successfully
    if (result != NULL) {
        // Insert multiple key-value pairs into the table to test its behavior
        for (size_t i = 0; i < size - 1; i += 2) {
            Janet key = janet_wrap_integer(data[i]);
            Janet value = janet_wrap_integer(data[i + 1]);
            janet_table_put(result, key, value);

            // Retrieve the value to ensure the table is functioning
            Janet retrieved = janet_table_get(result, key);

            // Check if the retrieved value matches the inserted value
            if (!janet_equals(retrieved, value)) {
                abort(); // Abort if there's a mismatch, indicating a potential issue
            }
        }

        // Additional operations to maximize fuzzing
        // e.g., remove a key-value pair
        if (size > 2) {
            Janet key_to_remove = janet_wrap_integer(data[0]);
            janet_table_remove(result, key_to_remove);
        }

        // Stress test with more operations
        for (size_t i = 0; i < size; ++i) {
            Janet key = janet_wrap_integer(data[i]);
            Janet value = janet_wrap_integer(data[size - i - 1]);
            janet_table_put(result, key, value);
            janet_table_get(result, key);
            janet_table_remove(result, key);
        }
    }

    // Clean up the Janet environment
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

    LLVMFuzzerTestOneInput_395(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
