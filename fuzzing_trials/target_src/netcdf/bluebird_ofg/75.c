#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_75(const uint8_t *data, size_t size) {
    // Ensure that the input data is large enough to extract necessary parameters
    if (size < 10) {
        return 0;
    }

    // Extract parameters from the input data
    int compound_id = (int)data[0];
    nc_type field_type = (nc_type)data[1];
    size_t field_size = (size_t)data[2];
    nc_type base_type = (nc_type)data[3];

    // Allocate memory for the field name and ensure it is null-terminated
    char field_name[6];
    memcpy(field_name, &data[4], 5);
    field_name[5] = '\0';

    // Call the function-under-test
    nc_insert_compound(compound_id, field_type, field_name, field_size, base_type);

    return 0;
}