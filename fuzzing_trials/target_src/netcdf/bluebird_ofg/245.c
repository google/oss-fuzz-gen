#include <stdint.h>
#include <stddef.h>

// Assume the function is defined elsewhere
extern int nc_get_var_ushort(int, int, unsigned short *);

int LLVMFuzzerTestOneInput_245(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract two integers and an unsigned short
    if (size < sizeof(int) * 2 + sizeof(unsigned short)) {
        return 0;
    }

    // Extract two integers and an unsigned short from the data
    int var1 = *(const int *)(data);
    int var2 = *(const int *)(data + sizeof(int));
    unsigned short var3 = *(const unsigned short *)(data + sizeof(int) * 2);

    // Call the function-under-test
    nc_get_var_ushort(var1, var2, &var3);

    return 0;
}