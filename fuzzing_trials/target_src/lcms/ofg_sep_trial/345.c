#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_345(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    int row, col;
    cmsFloat64Number result;

    // Initialize handle to a non-NULL value
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Ensure size is sufficient to extract row and col
    if (size < 2 * sizeof(int)) {
        cmsIT8Free(handle);
        return 0;
    }

    // Extract row and col from data
    row = *((int *)data);
    col = *((int *)(data + sizeof(int)));

    // Call the function-under-test
    result = cmsIT8GetDataRowColDbl(handle, row, col);

    // Clean up
    cmsIT8Free(handle);

    return 0;
}