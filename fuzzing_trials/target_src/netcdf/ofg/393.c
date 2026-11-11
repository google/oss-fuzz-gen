#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// Function-under-test declaration
const char * nc_inq_libvers();

// Fuzzing harness
int LLVMFuzzerTestOneInput_393(const uint8_t *data, size_t size) {
    // Call the function-under-test
    const char *version = nc_inq_libvers();

    // Print the result to ensure the function is called
    printf("Library version: %s\n", version);

    return 0;
}