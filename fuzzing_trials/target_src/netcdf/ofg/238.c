#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

// Function prototype for the function-under-test
int nc_rename_dim(int ncid, int dimid, const char *name);

int LLVMFuzzerTestOneInput_238(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient to extract parameters
    if (size < 3) {
        return 0;
    }

    // Extract parameters from the fuzzer input
    int ncid = (int)data[0];  // Use the first byte as ncid
    int dimid = (int)data[1]; // Use the second byte as dimid

    // Use the remaining data as the name, ensuring it's null-terminated
    size_t name_length = size - 2;
    char name[name_length + 1];
    memcpy(name, &data[2], name_length);
    name[name_length] = '\0';

    // Call the function-under-test
    nc_rename_dim(ncid, dimid, name);

    return 0;
}