#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_127(const uint8_t *data, size_t size) {
    // Ensure that the input data is large enough to split into necessary parts
    if (size < sizeof(size_t) * 2 + sizeof(int) * 2 + 1) {
        return 0;
    }

    // Create a copy of the input data to avoid modifying the const data
    uint8_t *data_copy = (uint8_t *)malloc(size);
    if (!data_copy) {
        return 0;
    }
    memcpy(data_copy, data, size);

    // Extract integers from the input data
    int ncid = *((int*)data_copy);
    int varid = *((int*)(data_copy + sizeof(int)));

    // Extract size_t values from the input data
    const size_t* start = (const size_t*)(data_copy + sizeof(int) * 2);
    const size_t* count = (const size_t*)(data_copy + sizeof(int) * 2 + sizeof(size_t));

    // Calculate remaining size for strings
    size_t remaining_size = size - (sizeof(int) * 2 + sizeof(size_t) * 2);

    // Ensure that there is at least one byte for a non-empty string
    if (remaining_size < 1) {
        free(data_copy);
        return 0;
    }

    // Use the remaining data as a string
    char* input_string = (char*)(data_copy + sizeof(int) * 2 + sizeof(size_t) * 2);
    size_t input_string_length = remaining_size;

    // Ensure null termination of the input string
    input_string[input_string_length - 1] = '\0';

    // Initialize a NetCDF file and variable for testing
    int retval;
    int test_ncid, test_varid;
    size_t dimlen = 1;
    int dimid;
    if ((retval = nc_create("test.nc", NC_CLOBBER, &test_ncid))) {
        free(data_copy);
        return 0;
    }
    if ((retval = nc_def_dim(test_ncid, "dim", dimlen, &dimid))) {
        nc_close(test_ncid);
        free(data_copy);
        return 0;
    }
    if ((retval = nc_def_var(test_ncid, "var", NC_STRING, 1, &dimid, &test_varid))) {
        nc_close(test_ncid);
        free(data_copy);
        return 0;
    }
    if ((retval = nc_enddef(test_ncid))) {
        nc_close(test_ncid);
        free(data_copy);
        return 0;
    }

    // Use the test_ncid and test_varid for the function-under-test
    const char* string_array[] = { input_string };
    int result = nc_put_vara_string(test_ncid, test_varid, start, count, string_array);

    // Close the NetCDF file
    nc_close(test_ncid);

    // Free the allocated copy of the data
    free(data_copy);

    return 0;
}