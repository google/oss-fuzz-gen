#include <janet.h>
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput_242(const uint8_t *data, size_t size) {
    if (size < sizeof(Janet)) {
        return 0;
    }

    // Initialize the Janet environment
    janet_init();

    // Create a new JanetTable
    JanetTable *table = janet_table(10);

    // Create a Janet key from the input data
    Janet key = janet_wrap_number((double)data[0]);

    // Create a pointer for the result table
    JanetTable *result_table = NULL;

    // Call the function-under-test
    Janet result = janet_table_get_ex(table, key, &result_table);

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

    LLVMFuzzerTestOneInput_242(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
