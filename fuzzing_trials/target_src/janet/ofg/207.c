#include <stdint.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_207(const uint8_t *data, size_t size) {
    // Initialize Janet runtime
    janet_init();

    // Create a Janet buffer from the input data
    JanetBuffer *buffer = janet_buffer(size);
    janet_buffer_push_bytes(buffer, data, size);

    // Convert the buffer to a Janet array
    Janet array = janet_wrap_array(janet_array(1));
    janet_array_push(janet_unwrap_array(array), janet_wrap_buffer(buffer));

    // Call the function-under-test
    janet_panicv(array);

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

    LLVMFuzzerTestOneInput_207(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
