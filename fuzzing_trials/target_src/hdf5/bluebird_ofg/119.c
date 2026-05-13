#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include "hdf5.h"

int LLVMFuzzerTestOneInput_119(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function-under-test
    hid_t file_id;
    H5F_libver_t low_bound;
    H5F_libver_t high_bound;

    // Ensure the size is sufficient to extract required values
    if (size < sizeof(hid_t) + 2 * sizeof(H5F_libver_t)) {
        return 0;
    }

    // Extract values from the input data
    file_id = *(const hid_t *)data;
    low_bound = *(const H5F_libver_t *)(data + sizeof(hid_t));
    high_bound = *(const H5F_libver_t *)(data + sizeof(hid_t) + sizeof(H5F_libver_t));

    // Call the function-under-test
    herr_t result = H5Fset_libver_bounds(file_id, low_bound, high_bound);

    // Return 0 since we are not interested in the result for fuzzing
    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_119(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
