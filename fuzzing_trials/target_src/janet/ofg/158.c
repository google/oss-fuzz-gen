#include <stdint.h>
#include <stdlib.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_158(const uint8_t *data, size_t size) {
    // Initialize the Janet environment
    janet_init();

    // Create a JanetTable with some initial size
    JanetTable *table = janet_table(10);

    // Ensure size is sufficient to extract a Janet key
    if (size < sizeof(Janet)) {
        janet_deinit();
        return 0;
    }

    // Create a Janet key from the fuzzing data
    Janet key = janet_wrap_number((double)data[0]); // Example: using the first byte as a number

    // Insert the key into the table with a dummy value
    janet_table_put(table, key, janet_wrap_nil());

    // Call the function-under-test
    JanetKV *result = janet_table_find(table, key);

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

    LLVMFuzzerTestOneInput_158(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
