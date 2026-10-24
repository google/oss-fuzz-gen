#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

// Fuzzer entry point
int LLVMFuzzerTestOneInput_130(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsHANDLE handle;
    char *formatString;

    // Ensure the data size is sufficient to create a string
    if (size < 1) {
        return 0;
    }

    // Allocate memory for the format string and copy data into it
    formatString = (char *)malloc(size + 1);
    if (formatString == NULL) {
        return 0;
    }
    memcpy(formatString, data, size);
    formatString[size] = '\0'; // Null-terminate the string

    // Create a dummy cmsHANDLE
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        free(formatString);
        return 0;
    }

    // Call the function-under-test
    cmsIT8DefineDblFormat(handle, formatString);

    // Clean up
    cmsIT8Free(handle);
    free(formatString);

    return 0;
}