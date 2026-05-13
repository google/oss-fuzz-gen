#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Mock function for nc_get_att_short_4 to demonstrate the fuzzing harness.
int nc_get_att_short_4(int ncid, int varid, const char *name, short *value) {
    // Simulated behavior for demonstration purposes.
    if (ncid < 0 || varid < 0 || name == NULL || value == NULL) {
        return -1; // Simulate an error condition.
    }
    *value = 42; // Assign a dummy value.
    return 0; // Simulate success.
}

int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our needs.
    if (size < 5) {
        return 0;
    }

    // Extract integers from the input data.
    int ncid = (int)data[0] & 0x7F; // Ensure non-negative by masking with 0x7F.
    int varid = (int)data[1] & 0x7F; // Ensure non-negative by masking with 0x7F.

    // Create a null-terminated string for the name with more characters.
    char name[3];
    name[0] = (char)data[2];
    name[1] = (char)data[3];
    name[2] = '\0';

    // Prepare a short to store the value.
    short value;

    // Call the function-under-test.
    nc_get_att_short_4(ncid, varid, name, &value);

    return 0;
}