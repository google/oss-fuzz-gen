#include <stdint.h>
#include <stdlib.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    // Initialize a JanetBuffer
    JanetBuffer buffer;
    janet_buffer_init(&buffer, 10); // Initialize with a capacity of 10

    // Ensure size is at least 4 bytes to read a uint32_t
    if (size < 4) {
        return 0;
    }

    // Read a uint32_t from the data
    uint32_t value = *(const uint32_t *)data;

    // Call the function-under-test
    janet_buffer_push_u32(&buffer, value);

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

    LLVMFuzzerTestOneInput_2(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
