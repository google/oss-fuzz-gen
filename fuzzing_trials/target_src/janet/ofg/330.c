#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_330(const uint8_t *data, size_t size) {
    // Initialize Janet
    janet_init();

    // Create a JanetBuffer
    JanetBuffer buffer;
    janet_buffer_init(&buffer, 10); // Initialize with a default size of 10

    // Ensure the data size is adequate for int32_t values
    if (size < 8) {
        janet_deinit();
        return 0;
    }

    // Extract two int32_t values from the data
    int32_t min_size = (int32_t)((data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]);
    int32_t growth_factor = (int32_t)((data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7]);

    // Ensure min_size is positive to avoid undefined behavior
    if (min_size < 0) {
        min_size = -(min_size);
    }

    // Call the function-under-test
    janet_buffer_ensure(&buffer, min_size, growth_factor);

    // Manipulate the buffer to increase the chance of finding issues
    for (size_t i = 0; i < size; i++) {
        janet_buffer_push_u8(&buffer, data[i]);
    }

    // Clean up
    janet_buffer_deinit(&buffer);
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

    LLVMFuzzerTestOneInput_330(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
