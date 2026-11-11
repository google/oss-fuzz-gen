#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_383(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    char *patchName;
    int result;

    // Initialize a cmsHANDLE with a non-NULL value
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0; // Allocation failed, exit early
    }

    // Ensure the data is null-terminated for use as a string
    patchName = (char *)malloc(size + 1);
    if (patchName == NULL) {
        cmsIT8Free(handle);
        return 0; // Allocation failed, exit early
    }
    memcpy(patchName, data, size);
    patchName[size] = '\0';

    // Call the function-under-test
    result = cmsIT8GetPatchByName(handle, patchName);

    // Clean up
    free(patchName);
    cmsIT8Free(handle);

    return 0;
}