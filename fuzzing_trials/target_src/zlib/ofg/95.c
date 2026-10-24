#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_95(const uint8_t *data, size_t size) {
    // Define and initialize variables for the function-under-test
    Bytef *dest;
    uLongf destLen;
    const Bytef *source = data;
    uLong sourceLen = (uLong)size;

    // Allocate memory for the destination buffer
    // Assuming the uncompressed data will not be larger than 10 times the compressed data
    destLen = size * 10;
    dest = (Bytef *)malloc(destLen);
    if (dest == NULL) {
        return 0;
    }

    // Call the function-under-test
    int result = uncompress2(dest, &destLen, source, &sourceLen);

    // Free allocated memory
    free(dest);

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

    LLVMFuzzerTestOneInput_95(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
