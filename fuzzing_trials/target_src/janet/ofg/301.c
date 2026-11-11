#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_301(const uint8_t *data, size_t size) {
    // Initialize the Janet environment
    janet_init();

    // Create two JanetTable objects
    JanetTable *table1 = janet_table(10); // Create a table with initial capacity
    JanetTable *table2 = janet_table(10); // Create another table with initial capacity

    // Populate the tables with some data
    // Note: This is a simple example. In reality, you might want to parse 'data' and 'size' to add entries
    for (size_t i = 0; i < size; i++) {
        Janet key = janet_wrap_integer((int32_t)i);
        Janet value = janet_wrap_integer((int32_t)data[i]);
        janet_table_put(table1, key, value);
        janet_table_put(table2, key, value);
    }

    // Call the function-under-test
    janet_table_merge_table(table1, table2);

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

    LLVMFuzzerTestOneInput_301(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
