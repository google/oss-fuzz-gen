#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_64(const uint8_t *data, size_t size) {
    // Create a temporary netCDF file
    const char *tmp_filename = "temp.nc";
    int ncid;
    int retval;

    // Create a new netCDF file
    if ((retval = nc_create(tmp_filename, NC_CLOBBER, &ncid))) {
        return 0; // If file creation fails, return
    }

    // Define a compound type for the test
    nc_type compound_type;
    if ((retval = nc_def_compound(ncid, sizeof(int), "compound_type", &compound_type))) {
        nc_close(ncid);
        return 0;
    }

    // End define mode
    if ((retval = nc_enddef(ncid))) {
        nc_close(ncid);
        return 0;
    }

    // Initialize the parameters for nc_inq_compound
    char name[256]; // Buffer for the name, ensure it's large enough
    size_t field_count = 0;
    size_t size_in_bytes = 0;

    // Ensure data is not NULL and size is sufficient for name
    if (size > 0) {
        // Copy some part of the data to the name buffer
        size_t name_len = size < sizeof(name) ? size : sizeof(name) - 1;
        memcpy(name, data, name_len);
        name[name_len] = '\0'; // Null-terminate the string
    } else {
        strcpy(name, "default_name"); // Use a default name if size is 0
    }

    // Call the function-under-test with a valid ncid and compound_type
    int result = nc_inq_compound(ncid, compound_type, name, &field_count, &size_in_bytes);

    // Close the netCDF file
    nc_close(ncid);

    // Use the result, field_count, and size_in_bytes as needed
    // For fuzzing, we can ignore the result

    return 0;
}