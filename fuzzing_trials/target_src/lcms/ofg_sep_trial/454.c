#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>  // Include for memcpy
#include <lcms2.h>

int LLVMFuzzerTestOneInput_454(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    void *memoryBuffer;
    cmsUInt32Number bufferSize;
    cmsBool result;

    // Initialize the handle with a non-NULL value
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Allocate memory for the buffer, ensuring it's not NULL
    memoryBuffer = malloc(size);
    if (memoryBuffer == NULL) {
        cmsIT8Free(handle);
        return 0;
    }

    // Copy data into the allocated memory buffer
    memcpy(memoryBuffer, data, size);

    // Initialize bufferSize with a non-NULL value
    bufferSize = (cmsUInt32Number)size;

    // Call the function-under-test
    result = cmsIT8SaveToMem(handle, memoryBuffer, &bufferSize);

    // Clean up
    free(memoryBuffer);
    cmsIT8Free(handle);

    return 0;
}