#include <stdint.h>
#include <stddef.h>
#include <janet.h>

// Initialize Janet runtime
static void initialize_janet_412() {
    static int initialized = 0;
    if (!initialized) {
        janet_init();
        initialized = 1;
    }
}

int LLVMFuzzerTestOneInput_412(const uint8_t *data, size_t size) {
    initialize_janet_412();

    // Create a JanetBuffer
    JanetBuffer *buffer = janet_buffer(10);

    // Ensure the data is not empty
    if (size == 0) {
        return 0;
    }

    // Use the first byte of data as an integer for indentation
    int indent = (int)data[0];

    // Use the second byte of data as an integer for flags
    int flags = (size > 1) ? (int)data[1] : 0;

    // Create a Janet value from the remaining data
    Janet janet_value;
    if (size > 2) {
        janet_value = janet_wrap_string(janet_string(data + 2, size - 2));
    } else {
        janet_value = janet_wrap_nil();
    }

    // Call the function-under-test
    janet_pretty(buffer, indent, flags, janet_value);

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

    LLVMFuzzerTestOneInput_412(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
