#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_477(const uint8_t *data, size_t size) {
    cmsHANDLE handle = cmsIT8Alloc(NULL);
    if (handle == NULL || size < sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Allocate memory for the output buffer
    void *outputBuffer = malloc(size);
    if (outputBuffer == NULL) {
        cmsIT8Free(handle);
        return 0;
    }

    // Use a portion of the input data to initialize cmsUInt32Number
    cmsUInt32Number outputSize = 0;
    memcpy(&outputSize, data, sizeof(cmsUInt32Number));

    // Call the function-under-test
    cmsBool result = cmsIT8SaveToMem(handle, outputBuffer, &outputSize);

    // Clean up
    free(outputBuffer);
    cmsIT8Free(handle);

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

    LLVMFuzzerTestOneInput_477(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
