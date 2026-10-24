#include <stdint.h>
#include <stdlib.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_120(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract two Janet values
    if (size < 2 * sizeof(Janet)) {
        return 0;
    }

    // Initialize Janet (required before using any Janet functions)
    janet_init();

    // Create a JanetTable
    JanetTable *table = janet_table(10); // Initial capacity of 10

    // Extract two Janet values from the input data
    Janet key = janet_wrap_integer(data[0]); // Use first byte as key
    Janet value = janet_wrap_integer(data[1]); // Use second byte as value

    // Call the function-under-test
    janet_table_put(table, key, value);

    // Clean up Janet (required after all Janet operations are done)
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

    LLVMFuzzerTestOneInput_120(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
