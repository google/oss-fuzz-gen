#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_347(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsHANDLE handle = cmsIT8Alloc(NULL);
    const char *propertyName = "SampleProperty";
    const char **propertyValues = NULL;

    // Ensure the data is not empty
    if (size == 0) {
        return 0;
    }

    // Call the function-under-test
    cmsUInt32Number result = cmsIT8EnumPropertyMulti(handle, propertyName, &propertyValues);

    // Clean up
    if (propertyValues != NULL) {
        free((void*)propertyValues);
    }
    cmsIT8Free(handle);

    return 0;
}