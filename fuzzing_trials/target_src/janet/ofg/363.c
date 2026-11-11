#include <stdint.h>
#include <stddef.h>
#include <janet.h>

// Define the LLVMFuzzerTestOneInput function
int LLVMFuzzerTestOneInput_363(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract necessary parameters
    if (size < sizeof(int32_t) + 2 * sizeof(Janet)) {
        return 0;
    }

    // Initialize Janet runtime
    janet_init();

    // Extract an int32_t index from the data
    int32_t index = *(int32_t *)data;
    data += sizeof(int32_t);
    size -= sizeof(int32_t);

    // Extract two Janet values from the data
    Janet value1 = *(Janet *)data;
    data += sizeof(Janet);
    size -= sizeof(Janet);

    Janet value2 = *(Janet *)data;
    data += sizeof(Janet);
    size -= sizeof(Janet);

    // Call the function-under-test
    janet_putindex(value1, index, value2);

    // Deinitialize Janet runtime
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

    LLVMFuzzerTestOneInput_363(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
