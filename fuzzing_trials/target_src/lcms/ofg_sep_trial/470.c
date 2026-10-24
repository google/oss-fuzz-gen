#include <stdint.h>
#include <stddef.h>

// Assuming the function is declared in a header file
void cmsUnregisterPlugins();

int LLVMFuzzerTestOneInput_470(const uint8_t *data, size_t size) {
    // Directly call the function-under-test
    cmsUnregisterPlugins();

    return 0;
}