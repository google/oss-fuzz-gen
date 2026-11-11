#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_100(const uint8_t *data, size_t size) {
    // Ensure that the input size is not zero to avoid unnecessary processing
    if (size == 0) {
        return 0;
    }

    // Allocate memory for the destination buffer
    uLongf destLen = size * 10; // Assume the uncompressed data is at most 10 times larger
    Bytef *dest = (Bytef *)malloc(destLen);
    if (dest == NULL) {
        return 0;
    }

    // Copy the input data to a source buffer
    Bytef *source = (Bytef *)malloc(size);
    if (source == NULL) {
        free(dest);
        return 0;
    }
    memcpy(source, data, size);

    // Call the function-under-test
    int result = uncompress(dest, &destLen, source, (uLong)size);

    // Free allocated memory
    free(dest);
    free(source);

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

    LLVMFuzzerTestOneInput_100(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
