#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_486(const uint8_t *data, size_t size) {
    JanetTable *table;
    Janet key, value, result;

    // Initialize the Janet runtime
    janet_init();

    // Create a new Janet table
    table = janet_table(10);

    // Ensure the table is not NULL
    if (table == NULL) {
        janet_deinit();
        return 0;
    }

    // Use the input data to populate the table
    for (size_t i = 0; i + 1 < size; i += 2) {
        key = janet_wrap_integer(data[i]);
        value = janet_wrap_integer(data[i + 1]);
        janet_table_put(table, key, value);
    }

    // Call the function-under-test with a valid key
    if (size > 0) {
        key = janet_wrap_integer(data[0]);
        result = janet_table_get(table, key);
    }

    // Clean up
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

    LLVMFuzzerTestOneInput_486(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
