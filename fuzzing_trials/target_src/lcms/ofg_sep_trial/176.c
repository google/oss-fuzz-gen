#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_176(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsHANDLE handle;
    char *setName;
    char *setValue;
    cmsFloat64Number value;

    // Ensure size is sufficient to extract necessary data
    if (size < sizeof(cmsFloat64Number) + 2) {
        return 0;
    }

    // Initialize handle
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Allocate memory for setName and setValue
    setName = (char *)malloc(2);
    setValue = (char *)malloc(2);

    if (setName == NULL || setValue == NULL) {
        cmsIT8Free(handle);
        free(setName);
        free(setValue);
        return 0;
    }

    // Copy data into setName and setValue
    strncpy(setName, (const char *)data, 1);
    setName[1] = '\0';
    strncpy(setValue, (const char *)(data + 1), 1);
    setValue[1] = '\0';

    // Extract cmsFloat64Number value from data
    memcpy(&value, data + 2, sizeof(cmsFloat64Number));

    // Call the function-under-test
    cmsIT8SetDataDbl(handle, setName, setValue, value);

    // Clean up
    cmsIT8Free(handle);
    free(setName);
    free(setValue);

    return 0;
}