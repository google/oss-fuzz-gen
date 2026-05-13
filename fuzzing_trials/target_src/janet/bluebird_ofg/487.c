#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_487(const uint8_t *data, size_t size) {
    // Initialize Janet runtime
    janet_init();

    // Create a JanetTable and populate it with some data
    JanetTable *table = janet_table(10);

    if (size > 0) {
        // Use the data to create a key-value pair in the JanetTable
        Janet key = janet_wrap_string(janet_string(data, size < 256 ? size : 256));
        Janet value = janet_wrap_integer(42); // Arbitrary non-null value

        // Put the key-value pair into the table
        janet_table_put(table, key, value);
    }

    // Call the function-under-test
    JanetTable *result = janet_env_lookup(table);

    // Clean up Janet runtime
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

    LLVMFuzzerTestOneInput_487(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
