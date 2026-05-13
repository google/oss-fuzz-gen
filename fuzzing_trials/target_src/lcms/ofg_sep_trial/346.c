#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_346(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    int row = 0;
    int col = 0;
    cmsFloat64Number result;

    // Initialize the handle with a non-NULL value for fuzzing
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Ensure size is sufficient to extract row and col
    if (size >= sizeof(int) * 2) {
        // Extract row and column from input data
        row = *((int*)data);
        col = *((int*)(data + sizeof(int)));
    }

    // Call the function-under-test
    result = cmsIT8GetDataRowColDbl(handle, row, col);

    // Cleanup
    cmsIT8Free(handle);

    return 0;
}