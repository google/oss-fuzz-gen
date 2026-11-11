#include <stdint.h>
#include <stdlib.h>
#include <janet.h>

// Function under test
JanetTable *janet_table_weakkv(int32_t size);

// Fuzzing harness
int LLVMFuzzerTestOneInput_320(const uint8_t *data, size_t size) {
    // Ensure that the input size is large enough to extract an int32_t
    if (size < sizeof(int32_t)) {
        return 0;
    }

    // Extract an int32_t from the input data
    int32_t table_size = *((int32_t *)data);

    // Ensure the table size is within a reasonable range to avoid potential issues
    // Adjust the range based on what is considered valid for your application
    if (table_size < 0 || table_size > 10000) { // Assuming 10000 is a reasonable upper limit
        return 0;
    }

    // Call the function under test
    JanetTable *table = janet_table_weakkv(table_size);

    // Perform some operations on the table to ensure it's being utilized
    if (table) {
        // Example operation: insert a key-value pair
        Janet key = janet_wrap_string(janet_cstring("example_key"));
        Janet value = janet_wrap_integer(42);
        janet_table_put(table, key, value);

        // Example operation: lookup the value
        Janet found_value = janet_table_get(table, key);
        if (!janet_checktype(found_value, JANET_NIL)) {
            // Successfully found the value
        }
    }

    // Normally, you would perform some operations on the table or verify its contents
    // For this fuzzing harness, we simply return after calling the function

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

    LLVMFuzzerTestOneInput_320(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
