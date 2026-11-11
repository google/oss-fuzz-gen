#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_122(const uint8_t *data, size_t size) {
    // Initialize the Janet environment
    janet_init();

    // Create a JanetTable with some dummy data
    JanetTable *table = janet_table(10);
    Janet key1 = janet_cstringv("key1");
    Janet value1 = janet_cstringv("value1");
    janet_table_put(table, key1, value1);

    Janet key2 = janet_cstringv("key2");
    Janet value2 = janet_cstringv("value2");
    janet_table_put(table, key2, value2);

    // Use the input data to create a Janet key
    Janet key;
    if (size > 0) {
        key = janet_wrap_integer(data[0]); // Use first byte as an integer key
    } else {
        key = janet_wrap_integer(0); // Default key if no data
    }

    // Call the function-under-test
    Janet result = janet_table_rawget(table, key);

    // Clean up the Janet environment
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

    LLVMFuzzerTestOneInput_122(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
