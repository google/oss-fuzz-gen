#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>  // Include standard library for abort function
#include "/src/janet/src/include/janet.h"

int LLVMFuzzerTestOneInput_171(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract an int32_t value
    if (size < sizeof(int32_t)) {
        return 0;
    }

    // Extract an int32_t value from the input data
    int32_t input_value = 0;
    for (size_t i = 0; i < sizeof(int32_t); i++) {
        input_value |= ((int32_t)data[i]) << (i * 8);
    }

    // Ensure the input_value is within a valid range for the function-under-test
    if (input_value <= 0) {
        return 0;
    }

    // Initialize Janet environment before calling any Janet functions
    janet_init();

    // Call the function-under-test
    JanetTable *table = janet_table_weakv(input_value);

    // Perform any additional operations if necessary
    // For this fuzzing harness, we just ensure the function is called

    // Clean up or further utilize the table if needed
    if (table) {
        // Example operation: check the table size or perform a dummy operation
        int32_t table_size = janet_tablen(table);
        (void)table_size; // Suppress unused variable warning
    }

    // Deinitialize Janet environment after operations
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

    LLVMFuzzerTestOneInput_171(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
