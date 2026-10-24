#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_384(const uint8_t *data, size_t size) {
    // Initialize the Janet environment
    janet_init();

    // Create a JanetTable
    JanetTable *table = janet_table(10);

    // Ensure size is sufficient for creating a Janet string
    if (size > 0) {
        // Create a Janet string from the input data
        Janet key = janet_stringv(data, size);

        // Insert a sample value into the table for the given key
        Janet value = janet_wrap_integer(42);
        janet_table_put(table, key, value);

        // Call the function-under-test
        Janet result = janet_table_get(table, key);

        // Use the result in some way to avoid unused variable warning
        if (janet_checktype(result, JANET_NUMBER)) {
            double num = janet_unwrap_number(result);
            (void)num; // Suppress unused variable warning
        }
    }

    // Cleanup the Janet environment
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

    LLVMFuzzerTestOneInput_384(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
