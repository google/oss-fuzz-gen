#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_131(const uint8_t *data, size_t size) {
    // Initialize variables needed for cmsIT8SetDataFormat
    cmsHANDLE handle;
    int index;
    const char *formatString;

    // Ensure size is sufficient to extract necessary data
    if (size < sizeof(int) + 1) {
        return 0;
    }

    // Initialize handle with a valid cmsHANDLE object
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Extract an integer from the data for the index
    memcpy(&index, data, sizeof(int));
    index = abs(index) % 100; // Ensure index is positive and within a reasonable range

    // Extract a string from the data for the formatString
    formatString = (const char *)(data + sizeof(int));

    // Call the function-under-test
    cmsBool result = cmsIT8SetDataFormat(handle, index, formatString);

    // Clean up
    cmsIT8Free(handle);

    return 0;
}