#include <stddef.h>
#include <stdint.h>

// Assuming the function is declared somewhere
int nc_get_var1_long(int ncid, int varid, const size_t *indexp, long *valuep);

int LLVMFuzzerTestOneInput_220(const uint8_t *data, size_t size) {
    if (size < sizeof(size_t)) {
        return 0; // Not enough data to form a valid input
    }

    // Extracting parameters from the data
    int ncid = (int)data[0]; // Using the first byte as an integer
    int varid = (int)data[1]; // Using the second byte as an integer

    // Ensure there's enough data to extract a size_t index
    size_t index = 0;
    if (size >= sizeof(size_t) + 2) {
        index = *((const size_t *)(data + 2)); // Extracting size_t index
    }

    long value = 0; // Initialize a long variable to receive the result

    // Call the function-under-test
    nc_get_var1_long(ncid, varid, &index, &value);

    return 0;
}