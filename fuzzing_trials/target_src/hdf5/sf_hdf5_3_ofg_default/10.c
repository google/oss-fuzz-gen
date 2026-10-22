#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Remove the 'extern "C"' linkage specification since this is C code, not C++
int LLVMFuzzerTestOneInput_10(const uint8_t *data, size_t size) {
    // Initialize HDF5 library
    H5open();

    // Create a temporary file to hold the HDF5 data
    hid_t file_id = H5Fcreate("temp.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Ensure data is null-terminated for string operations
    char group_name[256];
    size_t copy_size = size < 255 ? size : 255;
    memcpy(group_name, data, copy_size);
    group_name[copy_size] = '\0';

    // Use default property lists for creation, link, and group access
    hid_t gcpl_id = H5P_DEFAULT;
    hid_t lcpl_id = H5P_DEFAULT;
    hid_t gapl_id = H5P_DEFAULT;

    // Call the function-under-test
    hid_t group_id = H5Gcreate2(file_id, group_name, lcpl_id, gcpl_id, gapl_id);

    // Check if the group was created successfully
    if (group_id >= 0) {
        H5Gclose(group_id);
    }

    // Close the file
    H5Fclose(file_id);

    // Close the HDF5 library
    H5close();

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

    LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
