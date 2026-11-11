#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_149(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    char *filename;

    // Ensure there's enough data to create a filename
    if (size < 5) return 0;

    // Initialize handle
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Allocate memory for filename and copy data into it
    filename = (char *)malloc(size + 1);
    if (filename == NULL) {
        cmsIT8Free(handle);
        return 0;
    }
    memcpy(filename, data, size);
    filename[size] = '\0'; // Null-terminate the string

    // Call the function under test
    cmsBool result = cmsIT8SaveToFile(handle, filename);

    // Cleanup
    free(filename);
    cmsIT8Free(handle);

    return 0;
}