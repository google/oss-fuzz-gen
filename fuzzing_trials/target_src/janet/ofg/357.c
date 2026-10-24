#include <stdint.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_357(const uint8_t *data, size_t size) {
    // Initialize Janet VM
    janet_init();

    // Prepare Janet values
    Janet key, table;

    // Ensure size is sufficient for creating Janet values
    if (size >= sizeof(Janet) * 2) {
        // Use the data to create Janet values
        key = janet_wrap_integer((int32_t)data[0]);
        table = janet_wrap_table(janet_table(1));

        // Insert the key with some value in the table
        janet_table_put(janet_unwrap_table(table), key, janet_wrap_integer((int32_t)data[1]));

        // Call the function-under-test
        Janet result = janet_get(table, key);

        // Use the result to prevent compiler optimizations
        (void)result;
    }

    // Deinitialize Janet VM
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

    LLVMFuzzerTestOneInput_357(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
