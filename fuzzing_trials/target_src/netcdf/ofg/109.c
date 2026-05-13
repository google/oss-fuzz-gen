#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

// Assume that the function nc_put_var_uchar is declared in some included header file
// int nc_put_var_uchar(int, int, const unsigned char *);

extern int nc_put_var_uchar(int, int, const unsigned char *);

int LLVMFuzzerTestOneInput_109(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0; // Not enough data to extract two integers
    }

    // Extract two integers from the input data
    int var1 = (int)data[0];
    int var2 = (int)data[1];

    // Use the rest of the data as the unsigned char array
    const unsigned char *uchar_data = data + 2;
    size_t uchar_data_size = size - 2;

    // Ensure the uchar_data is not NULL and has at least one element
    if (uchar_data_size > 0) {
        nc_put_var_uchar(var1, var2, uchar_data);
    }

    return 0;
}