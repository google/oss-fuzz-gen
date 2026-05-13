#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

// Initialize the Janet environment
static void initialize_janet_314() {
    janet_init();
}

// Create a sample JanetTable for fuzzing
static JanetTable *create_sample_table(const uint8_t *data, size_t size) {
    JanetTable *table = janet_table(10);
    if (table) {
        // Add some sample data to the table
        janet_table_put(table, janet_ckeywordv("key1"), janet_wrap_integer(42));
        const uint8_t *str_value = (const uint8_t *)"value";
        janet_table_put(table, janet_ckeywordv("key2"), janet_wrap_string(janet_string(str_value, 5)));

        // Use fuzzing input to modify the table
        if (size > 0) {
            Janet key = janet_wrap_integer(data[0]);
            Janet value = janet_wrap_integer(size);
            janet_table_put(table, key, value);
        }
    }
    return table;
}

int LLVMFuzzerTestOneInput_314(const uint8_t *data, size_t size) {
    // Initialize Janet environment
    initialize_janet_314();

    // Create a sample table using fuzzing input
    JanetTable *original_table = create_sample_table(data, size);
    if (!original_table) {
        janet_deinit();
        return 0;
    }

    // Call the function-under-test
    JanetTable *cloned_table = janet_table_clone(original_table);

    // Clean up
    // Remove the manual deinitialization of the cloned table
    // as janet_deinit will handle the rest

    // Deinitialize Janet environment
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

    LLVMFuzzerTestOneInput_314(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
