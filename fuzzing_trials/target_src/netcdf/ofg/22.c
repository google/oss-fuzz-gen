#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_22(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our needs
    if (size < sizeof(int) + 1) {
        return 0;
    }

    // Extract an integer from the data for the ncid parameter
    int ncid = *(const int *)data;

    // Extract a string for the name parameter
    const char *name = (const char *)(data + sizeof(int));

    // Ensure the string is null-terminated
    size_t max_name_length = size - sizeof(int);
    char *name_buffer = (char *)malloc(max_name_length + 1);
    if (!name_buffer) {
        return 0;
    }
    strncpy(name_buffer, name, max_name_length);
    name_buffer[max_name_length] = '\0';

    // Prepare a pointer for the dimid parameter
    int dimid;
    
    // Call the function-under-test
    nc_inq_dimid(ncid, name_buffer, &dimid);

    // Clean up
    free(name_buffer);

    return 0;
}