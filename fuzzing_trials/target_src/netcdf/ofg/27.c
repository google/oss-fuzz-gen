#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h> // Include for memset

extern int nc_get_varm_float(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, const ptrdiff_t *imap, float *fp);

int LLVMFuzzerTestOneInput_27(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient to extract parameters
    if (size < 2 + 4 * sizeof(size_t) + 4 * sizeof(ptrdiff_t) + 6 * sizeof(float)) {
        return 0;
    }

    // Extract integer parameters
    int ncid = (int)data[0];
    int varid = (int)data[1];

    // Extract size_t parameters for start and count
    const size_t *start = (const size_t *)(data + 2);
    const size_t *count = (const size_t *)(data + 2 + 2 * sizeof(size_t));

    // Extract ptrdiff_t parameters for stride and imap
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + 2 + 4 * sizeof(size_t));
    const ptrdiff_t *imap = (const ptrdiff_t *)(data + 2 + 4 * sizeof(size_t) + 2 * sizeof(ptrdiff_t));

    // Extract float array
    const float *fp = (const float *)(data + 2 + 4 * sizeof(size_t) + 4 * sizeof(ptrdiff_t));

    // Initialize extracted arrays to prevent undefined behavior
    size_t start_arr[2] = {0};
    size_t count_arr[2] = {0};
    ptrdiff_t stride_arr[2] = {1, 1}; // Default to 1 to ensure non-zero stride
    ptrdiff_t imap_arr[2] = {1, 1};   // Default to 1 to ensure non-zero imap
    float fp_arr[6] = {0};

    memcpy(start_arr, start, 2 * sizeof(size_t));
    memcpy(count_arr, count, 2 * sizeof(size_t));
    memcpy(fp_arr, fp, 6 * sizeof(float));

    // Validate and adjust the parameters to ensure they are meaningful
    for (int i = 0; i < 2; i++) {
        if (count_arr[i] == 0) {
            count_arr[i] = 1; // Ensure count is non-zero
        }
        if (stride_arr[i] == 0) {
            stride_arr[i] = 1; // Ensure stride is non-zero
        }
        if (imap_arr[i] == 0) {
            imap_arr[i] = 1; // Ensure imap is non-zero
        }
    }

    // Call the function-under-test with initialized arrays
    nc_get_varm_float(ncid, varid, start_arr, count_arr, stride_arr, imap_arr, fp_arr);

    return 0;
}