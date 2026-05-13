#include <stdint.h>
#include <stdlib.h>
#include <janet.h>

// Fuzzing harness for janet_wrap_table
int LLVMFuzzerTestOneInput_167(const uint8_t *data, size_t size) {
    // Ensure that size is large enough to create a table
    if (size < sizeof(JanetKV)) {
        return 0;
    }

    // Initialize the Janet environment
    janet_init();

    // Create a JanetTable
    JanetTable *table = janet_table(10);

    // Populate the table with data
    for (size_t i = 0; i < size / sizeof(JanetKV); i++) {
        Janet key = janet_wrap_integer(i);
        Janet value = janet_wrap_integer(data[i]);
        janet_table_put(table, key, value);
    }

    // Call the function-under-test using the macro
    Janet result = janet_wrap_table(table);

    // Clean up
    janet_deinit();

    // Return 0 to indicate successful execution
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

    LLVMFuzzerTestOneInput_167(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
