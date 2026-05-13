#include <stddef.h>
#include <stdint.h>

// Assume this is the function-under-test
int nc_get_var1_ubyte(int ncid, int varid, const size_t *indexp, unsigned char *ip);

int LLVMFuzzerTestOneInput_405(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient for our needs
    if (size < sizeof(size_t) + sizeof(unsigned char)) {
        return 0;
    }

    // Initialize the parameters for the function-under-test
    int ncid = (int)data[0];
    int varid = (int)data[1];

    // Use the data to create a size_t index
    size_t index = 0;
    if (size >= sizeof(size_t)) {
        index = *(const size_t *)(data + 2);
    }
    const size_t *indexp = &index;

    // Use the data to initialize the output variable
    unsigned char ip = data[size - 1];
    unsigned char *ip_ptr = &ip;

    // Call the function-under-test
    nc_get_var1_ubyte(ncid, varid, indexp, ip_ptr);

    return 0;
}