#include <stddef.h>
#include <stdint.h>

extern int nc_get_var1_ushort(int ncid, int varid, const size_t *indexp, unsigned short *ushortp);

int LLVMFuzzerTestOneInput_432(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to extract required parameters
    if (size < sizeof(size_t) + sizeof(unsigned short)) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = (int)data[0]; // Use the first byte as ncid
    int varid = (int)data[1]; // Use the second byte as varid

    // Use the next bytes to construct a size_t index
    size_t index = 0;
    if (size >= sizeof(size_t) + 2) {
        index = *(const size_t *)(data + 2);
    }

    // Use the remaining bytes to construct an unsigned short
    unsigned short ushort_value = 0;
    if (size >= sizeof(size_t) + 2 + sizeof(unsigned short)) {
        ushort_value = *(const unsigned short *)(data + 2 + sizeof(size_t));
    }

    // Call the function-under-test
    nc_get_var1_ushort(ncid, varid, &index, &ushort_value);

    return 0;
}