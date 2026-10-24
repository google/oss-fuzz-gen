#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_159(const uint8_t *data, size_t size) {
    if (size < sizeof(Janet)) {
        return 0;
    }

    // Initialize Janet environment
    janet_init();

    // Create a JanetTable
    JanetTable *table = janet_table(10); // Initial capacity of 10

    // Create a Janet key from the input data
    Janet key = janet_wrap_number(*(double *)data);

    // Add some dummy data to the table for testing
    Janet value = janet_wrap_integer(42);
    janet_table_put(table, key, value);

    // Call the function-under-test
    JanetKV *result = janet_table_find(table, key);

    // Cleanup
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

    LLVMFuzzerTestOneInput_159(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
