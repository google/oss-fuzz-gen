#include <stdint.h>
#include <stddef.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_55(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Allocate memory for the compressed output
    uLongf compressedSize = compressBound(size);
    Bytef *compressedData = (Bytef *)malloc(compressedSize);
    if (compressedData == NULL) {
        return 0;
    }

    // Prepare the input data
    const Bytef *inputData = (const Bytef *)data;
    uLong inputSize = (uLong)size;

    // Compression level (0-9, where 9 is the maximum compression)
    int level = Z_BEST_COMPRESSION;

    // Call the function-under-test
    int result = compress2(compressedData, &compressedSize, inputData, inputSize, level);

    // Free the allocated memory
    free(compressedData);

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

    LLVMFuzzerTestOneInput_55(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
