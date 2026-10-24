#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_10(const uint8_t *data, size_t size) {
    // Ensure there is enough data to work with
    if (size < sizeof(Janet)) {
        return 0;
    }

    // Initialize Janet VM
    janet_init();

    // Create a JanetBuffer
    JanetBuffer *buffer = janet_buffer(10);

    // Extract a Janet value from the input data
    Janet janet_value;
    memcpy(&janet_value, data, sizeof(Janet));

    // Create a JanetTable
    JanetTable *table = janet_table(10);

    // Use a fixed integer for the flags parameter
    int flags = 0;

    // Call the function-under-test
    janet_marshal(buffer, janet_value, table, flags);

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

    LLVMFuzzerTestOneInput_10(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
