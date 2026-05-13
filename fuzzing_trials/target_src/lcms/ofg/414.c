#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_414(const uint8_t *data, size_t size) {
    // Ensure we have enough data to work with
    if (size < sizeof(cmsUInt32Number) * 2 + 1) {
        return 0;
    }

    // Initialize variables
    cmsHTRANSFORM transform = (cmsHTRANSFORM)(uintptr_t)data[0]; // Assuming first byte for transform
    const void *inputBuffer = (const void *)(data + 1); // Assuming input starts from the second byte
    void *outputBuffer = malloc(size - 1); // Allocate output buffer
    if (outputBuffer == NULL) {
        return 0; // Return if memory allocation fails
    }
    
    cmsUInt32Number inputStride = *(const cmsUInt32Number *)(data + 1); // Extract inputStride
    cmsUInt32Number outputStride = *(const cmsUInt32Number *)(data + 1 + sizeof(cmsUInt32Number)); // Extract outputStride

    // Call the function-under-test
    cmsDoTransformStride(transform, inputBuffer, outputBuffer, inputStride, outputStride);

    // Free allocated memory
    free(outputBuffer);

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

    LLVMFuzzerTestOneInput_414(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
