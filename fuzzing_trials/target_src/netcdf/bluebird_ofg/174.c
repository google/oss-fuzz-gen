#include <stddef.h>
#include <stdint.h>
#include <string.h> // Include for memcpy
#include <limits.h> // Include for ULONG_MAX

extern int nc_put_vara_ulonglong(int ncid, int varid, const size_t *start, const size_t *count, const unsigned long long *op);

int LLVMFuzzerTestOneInput_174(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for the required arrays
    if (size < 4 * sizeof(size_t) + sizeof(unsigned long long)) {
        return 0;
    }

    // Declare and initialize variables for function parameters
    int ncid = data[0] % 256; // Use input data for ncid, ensuring it's a valid range
    int varid = data[1] % 256; // Use input data for varid, ensuring it's a valid range

    // Initialize start and count arrays
    size_t start[2];
    size_t count[2];

    // Copy data into start and count arrays safely
    memcpy(start, data + 2, 2 * sizeof(size_t));
    memcpy(count, data + 2 + 2 * sizeof(size_t), 2 * sizeof(size_t));

    // Ensure count values are non-zero to maximize function call effectiveness
    if (count[0] == 0) count[0] = 1;
    if (count[1] == 0) count[1] = 1;

    // Initialize the data array for the unsigned long long values
    const unsigned long long *op = (const unsigned long long *)(data + 4 * sizeof(size_t));

    // Call the function-under-test
    int result = nc_put_vara_ulonglong(ncid, varid, start, count, op);

    // Optionally, you can add checks or logging here to verify the result
    // For example:
    // if (result != expected_value) {
    //     // Handle unexpected result
    // }

    return 0;
}