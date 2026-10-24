#include <stddef.h>
#include <stdint.h>

// Assume nc_get_var1_ushort is defined in an external library
extern int nc_get_var1_ushort(int ncid, int varid, const size_t *indexp, unsigned short *ushortp);

int LLVMFuzzerTestOneInput_433(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract the parameters
    if (size < sizeof(int) * 2 + sizeof(size_t) + sizeof(unsigned short)) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *(int *)(data);
    int varid = *(int *)(data + sizeof(int));
    const size_t *indexp = (const size_t *)(data + sizeof(int) * 2);
    unsigned short ushort_value = *(unsigned short *)(data + sizeof(int) * 2 + sizeof(size_t));
    unsigned short *ushortp = &ushort_value;

    // Call the function-under-test
    nc_get_var1_ushort(ncid, varid, indexp, ushortp);

    return 0;
}