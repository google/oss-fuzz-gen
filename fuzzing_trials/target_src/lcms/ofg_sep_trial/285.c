#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_285(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsHANDLE handle = NULL;
    char key[256];
    char subkey[256];

    // Ensure the input size is large enough to extract necessary data
    if (size < 2) {
        return 0;
    }

    // Initialize key and subkey with some default values
    snprintf(key, sizeof(key), "Key%02x", data[0]);
    snprintf(subkey, sizeof(subkey), "SubKey%02x", data[1]);

    // Create a cmsHANDLE using cmsIT8Alloc, assuming the library is initialized
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Call the function under test
    cmsFloat64Number result = cmsIT8GetDataDbl(handle, key, subkey);

    // Clean up
    cmsIT8Free(handle);

    return 0;
}