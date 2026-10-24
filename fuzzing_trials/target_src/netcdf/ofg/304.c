#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern int nc_get_varm_string(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, const ptrdiff_t *imap, char **stringp);

int LLVMFuzzerTestOneInput_304(const uint8_t *data, size_t size) {
    if (size < 16) {
        return 0; // Ensure there is enough data to proceed
    }

    // Extract values from the input data
    int ncid = data[0]; // Use the first byte for ncid
    int varid = data[1]; // Use the second byte for varid

    // Use the next bytes for start, count, stride, and imap
    size_t start[2] = {data[2], data[3]};
    size_t count[2] = {data[4], data[5]};
    ptrdiff_t stride[2] = {data[6], data[7]};
    ptrdiff_t imap[2] = {data[8], data[9]};

    // Allocate memory for the output string
    char *outputString = (char *)malloc(256); // Allocate 256 bytes for the string
    if (outputString == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Initialize the output string with some data
    strncpy(outputString, (const char *)(data + 10), size - 10 < 256 ? size - 10 : 256);

    // Call the function-under-test
    nc_get_varm_string(ncid, varid, start, count, stride, imap, &outputString);

    // Free the allocated memory
    free(outputString);

    return 0;
}