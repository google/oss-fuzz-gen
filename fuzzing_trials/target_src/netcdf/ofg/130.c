#include <stdint.h>
#include <stddef.h>

// Function-under-test declaration
int nc_def_var_deflate(int ncid, int varid, int shuffle, int deflate, int deflate_level);

int LLVMFuzzerTestOneInput_130(const uint8_t *data, size_t size) {
    if (size < 5) {
        return 0; // Not enough data to extract all parameters
    }

    // Extract variables for the function-under-test from the fuzzing input
    int ncid = data[0]; // Use first byte for ncid
    int varid = data[1]; // Use second byte for varid
    int shuffle = data[2] % 2; // Use third byte for shuffle (0 or 1)
    int deflate = data[3] % 2; // Use fourth byte for deflate (0 or 1)
    int deflate_level = data[4] % 10; // Use fifth byte for deflate_level (0-9)

    // Call the function-under-test
    nc_def_var_deflate(ncid, varid, shuffle, deflate, deflate_level);

    return 0;
}