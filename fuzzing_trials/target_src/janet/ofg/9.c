#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_9(const uint8_t *data, size_t size) {
    // Initialize Janet environment
    janet_init();

    // Create a JanetBuffer
    JanetBuffer *buffer = janet_buffer(size);
    if (buffer == NULL) {
        janet_deinit();
        return 0;
    }

    // Create a Janet object from the data
    Janet janet_data;
    if (size >= sizeof(Janet)) {
        janet_data = *(Janet *)data;
    } else {
        janet_data = janet_wrap_nil();
    }

    // Create a JanetTable
    JanetTable *table = janet_table(10);
    if (table == NULL) {
        janet_deinit();
        return 0;
    }

    // Define an integer option
    int options = 0; // You can modify this to test different options

    // Call the function-under-test
    janet_marshal(buffer, janet_data, table, options);

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

    LLVMFuzzerTestOneInput_9(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
