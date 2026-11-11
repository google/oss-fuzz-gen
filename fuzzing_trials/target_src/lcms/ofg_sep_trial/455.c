#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_455(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    void *buffer;
    cmsUInt32Number bufferSize;
    cmsBool result;

    // Initialize LCMS handle
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Allocate memory for the buffer
    bufferSize = size + 1; // Ensure buffer is not NULL
    buffer = malloc(bufferSize);
    if (buffer == NULL) {
        cmsIT8Free(handle);
        return 0;
    }

    // Copy the data into the buffer
    memcpy(buffer, data, size);
    ((char*)buffer)[size] = '\0'; // Null-terminate to avoid issues with string functions

    // Call the function under test
    result = cmsIT8SaveToMem(handle, buffer, &bufferSize);

    // Clean up
    free(buffer);
    cmsIT8Free(handle);

    return 0;
}