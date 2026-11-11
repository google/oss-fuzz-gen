#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_565(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient to create meaningful inputs
    if (size < 5) {
        return 0;
    }

    // Extract an integer from the data
    int ncid = (int)data[0];

    // Extract a string from the data
    char name[256];
    size_t name_len = (size - 1 < 255) ? size - 1 : 255;
    memcpy(name, data + 1, name_len);
    name[name_len] = '\0'; // Null-terminate the string

    // Prepare an integer pointer
    int out_ncid;
    int *out_ncid_ptr = &out_ncid;

    // Call the function-under-test
    int result = nc_inq_ncid(ncid, name, out_ncid_ptr);

    // Print the result for debugging purposes (optional)
    printf("Result: %d, Output NCID: %d\n", result, out_ncid);

    return 0;
}