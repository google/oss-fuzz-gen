#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_189(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    char *columnName;

    // Initialize handle with a dummy IT8 structure
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Ensure the data is null-terminated to be used as a string
    columnName = (char *)malloc(size + 1);
    if (columnName == NULL) {
        cmsIT8Free(handle);
        return 0;
    }
    memcpy(columnName, data, size);
    columnName[size] = '\0';

    // Call the function under test
    cmsIT8SetIndexColumn(handle, columnName);

    // Clean up
    free(columnName);
    cmsIT8Free(handle);

    return 0;
}