#include <stdint.h>
#include <stddef.h>

// Assuming nc_finalize is declared in a header file included here
// #include "your_header_file.h"

extern int nc_finalize();

int LLVMFuzzerTestOneInput_256(const uint8_t *data, size_t size) {
    // Call the function-under-test
    int result = nc_finalize();

    // Return 0 as the function signature for LLVMFuzzerTestOneInput requires
    return 0;
}