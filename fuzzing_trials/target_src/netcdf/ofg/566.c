#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_566(const uint8_t *data, size_t size) {
    // Ensure the size is large enough to extract meaningful data
    if (size < sizeof(int) + 1) {
        return 0;
    }

    // Extract an integer from the input data
    int ncid = *(int *)data;

    // Allocate memory for the name and ensure it's null-terminated
    size_t name_len = size - sizeof(int);
    char *name = (char *)malloc(name_len + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, data + sizeof(int), name_len);
    name[name_len] = '\0';

    // Prepare an integer pointer to store the result
    int result_ncid;
    
    // Call the function-under-test
    nc_inq_ncid(ncid, name, &result_ncid);

    // Clean up
    free(name);

    return 0;
}