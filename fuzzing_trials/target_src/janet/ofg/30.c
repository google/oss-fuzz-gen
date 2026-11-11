#include <stdint.h>
#include <stddef.h>
#include <janet.h>

// Ensure Janet is initialized
__attribute__((constructor))
static void init_janet(void) {
    janet_init();
}

// Fuzzing harness
int LLVMFuzzerTestOneInput_30(const uint8_t *data, size_t size) {
    JanetBuffer buffer;
    Janet janet_value;
    
    // Initialize the Janet buffer
    janet_buffer_init(&buffer, 10);

    // Create a Janet value from the input data
    if (size > 0) {
        janet_value = janet_wrap_string(janet_string(data, size));
    } else {
        janet_value = janet_wrap_nil();
    }

    // Call the function under test
    janet_to_string_b(&buffer, janet_value);

    // Clean up
    janet_buffer_deinit(&buffer);

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

    LLVMFuzzerTestOneInput_30(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
