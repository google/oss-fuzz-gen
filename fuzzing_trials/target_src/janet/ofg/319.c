#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <janet.h>

// Ensure the Janet library is properly initialized before using any of its functions
void initialize_janet_319() {
    static int initialized = 0;
    if (!initialized) {
        janet_init();
        initialized = 1;
    }
}

extern JanetTable * janet_table_weakkv(int32_t);

int LLVMFuzzerTestOneInput_319(const uint8_t *data, size_t size) {
    if (size < sizeof(int32_t)) {
        return 0;
    }

    // Initialize Janet environment
    initialize_janet_319();

    // Extract an int32_t value from the input data
    int32_t input_value;
    memcpy(&input_value, data, sizeof(int32_t));

    // Call the function-under-test
    JanetTable *table = janet_table_weakkv(input_value);

    // Use the table in some way if needed, or just return
    // For fuzzing purposes, we can just ensure the function is called
    // Ensure the table is not NULL before using it
    if (table != NULL) {
        // Example usage of the table to ensure it's utilized
        // Insert a dummy key-value pair into the table
        Janet key = janet_wrap_integer(1);
        Janet value = janet_wrap_integer(42);
        janet_table_put(table, key, value);

        // Retrieve the value to ensure the table is functioning
        Janet retrieved_value = janet_table_get(table, key);
        if (!janet_checktype(retrieved_value, JANET_NIL)) {
            // Optionally, perform operations on the retrieved value
        }

        // Additional operations to maximize fuzzing effectiveness:
        // Insert multiple key-value pairs into the table
        for (int i = 2; i <= 10; i++) {
            Janet new_key = janet_wrap_integer(i);
            Janet new_value = janet_wrap_integer(i * 10);
            janet_table_put(table, new_key, new_value);
        }

        // Retrieve and validate inserted values
        for (int i = 2; i <= 10; i++) {
            Janet new_key = janet_wrap_integer(i);
            Janet retrieved_value = janet_table_get(table, new_key);
            if (!janet_checktype(retrieved_value, JANET_NIL)) {
                // Optionally, perform operations on the retrieved value
            }
        }

        // Attempt to trigger edge cases by using extreme values
        Janet extreme_key = janet_wrap_integer(INT32_MAX);
        Janet extreme_value = janet_wrap_integer(INT32_MIN);
        janet_table_put(table, extreme_key, extreme_value);
        Janet extreme_retrieved_value = janet_table_get(table, extreme_key);
        if (!janet_checktype(extreme_retrieved_value, JANET_NIL)) {
            // Optionally, perform operations on the retrieved value
        }
    }

    // Clean up Janet environment if needed
    // janet_deinit(); // Uncomment if you need to deinitialize after each run

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

    LLVMFuzzerTestOneInput_319(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
