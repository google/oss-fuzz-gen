#include <stdint.h>
#include <stdlib.h>
#include <janet.h>

// Define the fuzzing function without extern "C"
int LLVMFuzzerTestOneInput_195(const uint8_t *data, size_t size) {
    // Ensure that the size is large enough to extract an int32_t value
    if (size < sizeof(int32_t)) {
        return 0;
    }

    // Extract an int32_t value from the input data
    int32_t capacity = *(const int32_t *)data;

    // Ensure capacity is positive to avoid potential issues
    if (capacity <= 0) {
        capacity = 1; // Set a minimum capacity to ensure the table is created
    }

    // Initialize a JanetTable
    JanetTable table;
    JanetTable *result = janet_table_init_raw(&table, capacity);

    // Use the result in some way to avoid compiler optimizations
    if (result == NULL) {
        return 0;
    }

    // Use more of the input data to drive fuzzing
    size_t offset = sizeof(int32_t);
    while (offset + sizeof(int32_t) * 2 <= size) {
        int32_t key_value = *(const int32_t *)(data + offset);
        int32_t value_value = *(const int32_t *)(data + offset + sizeof(int32_t));
        offset += sizeof(int32_t) * 2;

        // Insert data into the table
        Janet key = janet_wrap_integer(key_value);
        Janet value = janet_wrap_integer(value_value);
        janet_table_put(result, key, value);

        // Retrieve and verify the value
        Janet retrieved_value = janet_table_get(result, key);
        if (janet_unwrap_integer(retrieved_value) != value_value) {
            return 0;
        }
    }

    // Perform additional operations to maximize fuzzing effectiveness
    // Insert more entries to potentially uncover memory issues
    for (int i = 0; i < 10; i++) {
        Janet dynamic_key = janet_wrap_integer(i);
        Janet dynamic_value = janet_wrap_integer(i * 2);
        janet_table_put(result, dynamic_key, dynamic_value);

        // Retrieve and verify the value
        Janet retrieved_dynamic_value = janet_table_get(result, dynamic_key);
        if (janet_unwrap_integer(retrieved_dynamic_value) != i * 2) {
            return 0;
        }
    }

    // Introduce random deletions to test table state changes
    for (int i = 0; i < 5; i++) {
        Janet random_key = janet_wrap_integer(i);
        janet_table_remove(result, random_key);
    }

    // Additional dynamic operations
    for (int i = 0; i < 5; i++) {
        int32_t random_key_value = rand() % 100;
        Janet random_key = janet_wrap_integer(random_key_value);
        Janet random_value = janet_wrap_integer(rand() % 200);
        janet_table_put(result, random_key, random_value);

        // Retrieve and verify the value
        Janet retrieved_random_value = janet_table_get(result, random_key);
        if (janet_unwrap_integer(retrieved_random_value) != janet_unwrap_integer(random_value)) {
            return 0;
        }
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

    LLVMFuzzerTestOneInput_195(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
