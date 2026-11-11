#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_323(const uint8_t *data, size_t size) {
    // Initialize Janet runtime
    janet_init();

    // Create a JanetTable
    JanetTable *table = janet_table(10);

    // Ensure that the data is not empty
    if (size < 2) { // Need at least two bytes for meaningful key-value pair
        janet_deinit();
        return 0;
    }

    // Use more of the data to create keys and values for the JanetTable
    for (size_t i = 0; i < size - 1; i += 2) {
        // Use two consecutive bytes as key and value
        Janet key = janet_wrap_integer(data[i]);
        Janet value = janet_wrap_integer(data[i + 1]);

        // Call the function under test
        janet_table_put(table, key, value);
    }

    // Clean up the Janet runtime
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

    LLVMFuzzerTestOneInput_323(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
