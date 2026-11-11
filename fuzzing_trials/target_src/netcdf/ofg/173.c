#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_173(const uint8_t *data, size_t size) {
    // Declare and initialize the parameters for nc_put_vara_schar
    int ncid = 0;  // Assuming a valid file ID, replace with actual valid ID if needed
    int varid = 0; // Assuming a valid variable ID, replace with actual valid ID if needed

    // Define the number of dimensions (for example, 2)
    size_t ndims = 2;
    size_t start[ndims];
    size_t count[ndims];

    // Initialize start and count arrays
    for (size_t i = 0; i < ndims; i++) {
        start[i] = 0; // Starting index for each dimension
        count[i] = 1; // Number of elements to write in each dimension
    }

    // Ensure the data size is sufficient for the signed char array
    if (size < sizeof(signed char)) {
        return 0;
    }

    // Create a signed char array from the data
    const signed char *schar_data = (const signed char *)data;

    // Call the function-under-test
    int result = nc_put_vara_schar(ncid, varid, start, count, schar_data);

    // Print the result for debugging purposes
    printf("nc_put_vara_schar result: %d\n", result);

    return 0;
}