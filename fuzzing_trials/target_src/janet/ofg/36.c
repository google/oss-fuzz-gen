#include <stdint.h>
#include <stddef.h>
#include <janet.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput_36(const uint8_t *data, size_t size) {
    // Ensure that the size is at least the size of an int32_t
    if (size < sizeof(int32_t)) {
        return 0;
    }

    // Extract an int32_t value from the input data
    int32_t input_value = 0;
    for (size_t i = 0; i < sizeof(int32_t); i++) {
        input_value |= ((int32_t)data[i]) << (i * 8);
    }

    // Ensure the input_value is positive and non-zero to avoid potential issues
    if (input_value <= 0) {
        input_value = 1; // Set to a minimum valid size
    }

    // Initialize the Janet runtime
    janet_init();

    // Call the function-under-test
    JanetTable *table = janet_table(input_value);

    // Perform operations on the table to maximize fuzzing effectiveness
    // For example, inserting multiple dummy key-value pairs
    for (int i = 0; i < input_value; i++) {
        char key_str[20];
        char value_str[20];
        snprintf(key_str, sizeof(key_str), "key%d", i);
        snprintf(value_str, sizeof(value_str), "value%d", i);
        Janet key = janet_cstringv(key_str);
        Janet value = janet_cstringv(value_str);
        janet_table_put(table, key, value);
    }

    // Attempt to retrieve some values to test table integrity
    for (int i = 0; i < input_value; i++) {
        char key_str[20];
        snprintf(key_str, sizeof(key_str), "key%d", i);
        Janet key = janet_cstringv(key_str);
        Janet retrieved_value = janet_table_get(table, key);
        // Optionally, perform some checks or operations on retrieved_value
        if (janet_checktype(retrieved_value, JANET_STRING)) {
            const uint8_t *str = janet_unwrap_string(retrieved_value);
            // Perform some dummy operations to ensure the string is valid
            if (str) {
                size_t len = janet_string_length(str);
                for (size_t j = 0; j < len; j++) {
                    volatile uint8_t c = str[j]; // Prevent compiler optimization
                    (void)c;
                }
            }
        }
    }

    // Deinitialize the Janet runtime
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

    LLVMFuzzerTestOneInput_36(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
