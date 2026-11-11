#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_33(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsHANDLE handle;
    const char *setName = "SampleSetName";
    const char *fieldName = "SampleFieldName";
    const char *fieldValue = "SampleFieldValue";

    // Ensure data size is sufficient for creating a valid handle
    if (size < sizeof(cmsHANDLE)) {
        return 0;
    }

    // Create a handle using cmsIT8Alloc
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsBool result = cmsIT8SetData(handle, setName, fieldName, fieldValue);

    // Clean up
    cmsIT8Free(handle);

    return 0;
}