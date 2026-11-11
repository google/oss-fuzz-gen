#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// Function under test
const char *nc_inq_libvers();

int LLVMFuzzerTestOneInput_392(const uint8_t *data, size_t size) {
    // Call the function under test
    const char *version = nc_inq_libvers();

    // Print the version string for debugging purposes
    // (In a real fuzzing scenario, you might not print, but it's useful for verification)
    printf("NetCDF Library Version: %s\n", version);

    return 0;
}