#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_359(const uint8_t *data, size_t size) {
    if (size < 2) return 0; // Ensure there's enough data for the fuzzing

    // Initialize parameters for nc_put_att_string
    int ncid = (int)data[0]; // Use first byte as ncid
    int varid = (int)data[1]; // Use second byte as varid

    // Create a non-null attribute name
    const char *name = "fuzz_attribute";

    // Ensure there is at least one string in the array
    size_t len = 1;

    // Allocate memory for the array of strings
    const char **stringArray = (const char **)malloc(len * sizeof(char *));
    if (stringArray == NULL) return 0; // Check for allocation failure

    // Create a non-null string to add as an attribute
    const char *attributeString = "fuzz_string";
    stringArray[0] = attributeString;

    // Call the function-under-test
    nc_put_att_string(ncid, varid, name, len, stringArray);

    // Free allocated memory
    free(stringArray);

    return 0;
}