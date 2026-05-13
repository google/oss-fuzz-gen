#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_188(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    char *columnName;

    // Initialize handle with a non-NULL value
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Allocate memory for columnName and ensure it's null-terminated
    columnName = (char *)malloc(size + 1);
    if (columnName == NULL) {
        cmsIT8Free(handle);
        return 0;
    }

    memcpy(columnName, data, size);
    columnName[size] = '\0';  // Null-terminate the string

    // Call the function-under-test
    cmsBool result = cmsIT8SetIndexColumn(handle, columnName);

    // Clean up
    free(columnName);
    cmsIT8Free(handle);

    return 0;
}