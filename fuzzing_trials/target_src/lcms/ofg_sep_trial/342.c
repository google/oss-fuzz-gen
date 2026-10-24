#include <stdint.h>
#include <stddef.h>
#include <lcms2_plugin.h>
#include <lcms2.h> // Include the main lcms2 library for the necessary functions and types

int LLVMFuzzerTestOneInput_342(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    cmsUInt32Number tableIndex;

    // Initialize the handle with a valid IT8 handle
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0; // Return if handle allocation fails
    }

    // Ensure size is sufficient to extract a cmsUInt32Number
    if (size < sizeof(cmsUInt32Number)) {
        cmsIT8Free(handle);
        return 0;
    }

    // Extract a cmsUInt32Number from the input data
    tableIndex = *(const cmsUInt32Number*)data;

    // Call the function under test
    cmsInt32Number result = cmsIT8SetTable(handle, tableIndex);

    // Free the allocated IT8 handle
    cmsIT8Free(handle);

    return 0;
}