#include <stdint.h>
#include <stdlib.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_317(const uint8_t *data, size_t size) {
    // Initialize Janet runtime
    janet_init();

    // Create a JanetBuffer and fill it with data
    JanetBuffer *buffer = janet_buffer(size);
    if (buffer == NULL) {
        janet_deinit();
        return 0;
    }

    // Copy data into the buffer
    for (size_t i = 0; i < size; i++) {
        janet_buffer_push_u8(buffer, data[i]);
    }

    // Wrap the buffer in a Janet type
    Janet wrapped_buffer = janet_wrap_buffer(buffer);

    // Call the function-under-test
    JanetBuffer *result_buffer = janet_unwrap_buffer(wrapped_buffer);

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

    LLVMFuzzerTestOneInput_317(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
