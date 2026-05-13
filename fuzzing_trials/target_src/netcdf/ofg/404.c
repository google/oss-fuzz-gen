#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// Assuming the function is defined in some library
extern int nc_get_var1_ubyte(int ncid, int varid, const size_t *indexp, unsigned char *valuep);

int LLVMFuzzerTestOneInput_404(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for our needs
    if (size < sizeof(size_t) + sizeof(unsigned char)) {
        return 0;
    }

    // Initialize parameters for the function
    int ncid = (int)data[0]; // Using the first byte as an integer
    int varid = (int)data[1]; // Using the second byte as an integer

    // Allocate memory for indexp and valuep
    size_t *indexp = (size_t *)malloc(sizeof(size_t));
    unsigned char *valuep = (unsigned char *)malloc(sizeof(unsigned char));

    // Ensure memory allocation was successful
    if (indexp == NULL || valuep == NULL) {
        free(indexp);
        free(valuep);
        return 0;
    }

    // Initialize indexp and valuep with data from the input
    *indexp = (size_t)data[2]; // Using the third byte as a size_t
    *valuep = data[3]; // Using the fourth byte as an unsigned char

    // Call the function-under-test
    int result = nc_get_var1_ubyte(ncid, varid, indexp, valuep);

    // Clean up
    free(indexp);
    free(valuep);

    return 0;
}