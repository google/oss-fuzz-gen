#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_343(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    int index;
    char patchName[256]; // Assuming a reasonable size for the patch name
    const char *result;

    // Initialize handle with a valid cmsHANDLE
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Use some data from the input to set the index
    if (size > 0) {
        index = data[0] % 256; // Example to limit the index to a reasonable range
    } else {
        index = 0; // Default index if no data is available
    }

    // Initialize patchName with some data
    if (size > 1) {
        strncpy(patchName, (const char *)data + 1, sizeof(patchName) - 1);
        patchName[sizeof(patchName) - 1] = '\0'; // Ensure null-termination
    } else {
        strcpy(patchName, "default_patch_name");
    }

    // Call the function-under-test
    result = cmsIT8GetPatchName(handle, index, patchName);

    // Clean up
    cmsIT8Free(handle);

    return 0;
}