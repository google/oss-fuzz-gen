#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_478(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    void *memoryBuffer;
    cmsUInt32Number bufferSize;
    cmsBool result;

    // Initialize handle with a valid IT8 table
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Initialize memoryBuffer with a non-null value
    memoryBuffer = malloc(size);
    if (memoryBuffer == NULL) {
        cmsIT8Free(handle);
        return 0;
    }
    memcpy(memoryBuffer, data, size);

    // Initialize bufferSize with a non-zero value
    bufferSize = (cmsUInt32Number)size;

    // Call the function-under-test
    result = cmsIT8SaveToMem(handle, memoryBuffer, &bufferSize);

    // Clean up
    free(memoryBuffer);
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

    LLVMFuzzerTestOneInput_478(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
