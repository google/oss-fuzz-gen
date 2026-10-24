#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_324(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    // Create a dummy file ID
    int file_id = 1;  // Assuming a valid file ID for fuzzing purposes

    // Allocate memory for the type name and ensure it's null-terminated
    char *type_name = (char *)malloc(size + 1);
    if (type_name == NULL) {
        return 0;
    }
    memcpy(type_name, data, size);
    type_name[size] = '\0';

    // Create a variable for nc_type
    nc_type type_id;

    // Call the function-under-test
    nc_inq_typeid(file_id, type_name, &type_id);

    // Free allocated memory
    free(type_name);

    return 0;
}