#include <stdint.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_44(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient to extract a uLong
    if (size < sizeof(uLong)) {
        return 0;
    }

    // Extract a uLong from the input data
    uLong input_value = 0;
    for (size_t i = 0; i < sizeof(uLong); i++) {
        input_value |= ((uLong)data[i]) << (i * 8);
    }

    // Call the function-under-test
    uLong result = compressBound(input_value);

    // Use the result in some way to avoid compiler optimizations
    (void)result;

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_44(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
