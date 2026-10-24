#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "hdf5.h"

int LLVMFuzzerTestOneInput_55(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    hid_t file_id;
    double hit_rate = 0.0;
    herr_t status;

    // Create a unique file name for the HDF5 file
    const char *file_name = "fuzz_test.h5";

    // Ensure that the size is sufficient to perform operations
    if (size < 1) {
        return 0;
    }

    // Create an HDF5 file to obtain a valid file identifier
    file_id = H5Fcreate(file_name, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);

    // Call the function-under-test
    status = H5Fget_mdc_hit_rate(file_id, &hit_rate);

    // Close the HDF5 file
    H5Fclose(file_id);

    // Return 0 to indicate successful execution
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

    LLVMFuzzerTestOneInput_55(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
