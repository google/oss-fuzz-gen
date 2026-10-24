#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Dummy implementation of nc_get_var1_uchar_102 for compilation purposes
// Replace this with the actual implementation when running the fuzzer
int nc_get_var1_uchar_102(int ncid, int varid, const size_t *indexp, unsigned char *ip) {
    // Simulate some processing
    if (ncid < 0 || varid < 0 || indexp == NULL || ip == NULL) {
        return -1; // Simulate an error condition
    }
    // Simulate setting the value pointed by ip
    *ip = (unsigned char)(*indexp % 256);
    return 0;
}

int LLVMFuzzerTestOneInput_102(const uint8_t *data, size_t size) {
    if (size < sizeof(size_t) + sizeof(unsigned char) + 2) {
        return 0;
    }

    // Initialize parameters for nc_get_var1_uchar_102
    int ncid = (int)data[0];
    int varid = (int)data[1];

    // Extract a size_t index from the data
    size_t index;
    memcpy(&index, data + 2, sizeof(size_t));

    // Extract an unsigned char value from the data
    unsigned char uchar_value;
    memcpy(&uchar_value, data + 2 + sizeof(size_t), sizeof(unsigned char));

    // Ensure index is within a reasonable range for better coverage
    index = index % 1000; // Limit index to a smaller range

    // Call the function-under-test
    int result = nc_get_var1_uchar_102(ncid, varid, &index, &uchar_value);

    // Use the result to simulate further processing
    if (result != 0) {
        // Handle error condition
        return 0;
    }

    // Additional logic could be added here to further explore function behavior
    // For example, check if uchar_value was modified as expected
    if (uchar_value != (unsigned char)(index % 256)) {
        // Handle unexpected behavior
        return 0;
    }

    return 0;
}