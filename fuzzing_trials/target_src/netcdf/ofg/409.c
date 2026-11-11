#include <stdint.h>
#include <stddef.h>

// Assuming the function is defined somewhere
int nc_get_var_ushort(int param1, int param2, unsigned short *result);

int LLVMFuzzerTestOneInput_409(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract two integers and an unsigned short
    if (size < sizeof(int) * 2 + sizeof(unsigned short)) {
        return 0;
    }

    // Extract two integers and an unsigned short from the data
    int param1 = *(const int *)data;
    int param2 = *(const int *)(data + sizeof(int));
    unsigned short result;

    // Call the function-under-test
    nc_get_var_ushort(param1, param2, &result);

    return 0;
}