#include <stdint.h>
#include <stddef.h>

// Assuming the function is defined in some library
extern int nc_inq_base_pe(int, int *);

int LLVMFuzzerTestOneInput_35(const uint8_t *data, size_t size) {
    int param1;
    int param2;

    // Ensure there is enough data to initialize both parameters
    if (size < sizeof(int) * 2) {
        return 0;
    }

    // Initialize parameters from the input data
    param1 = *(int *)data;
    param2 = *(int *)(data + sizeof(int));

    // Call the function-under-test
    nc_inq_base_pe(param1, &param2);

    return 0;
}