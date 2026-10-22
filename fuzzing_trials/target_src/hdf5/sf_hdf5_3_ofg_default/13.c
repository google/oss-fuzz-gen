#include <stdint.h>
#include <stdlib.h>
#include <string.h>  // Include this for memcpy
#include <hdf5.h>

int LLVMFuzzerTestOneInput_13(const uint8_t *data, size_t size) {
    // Ensure there is enough data for a null-terminated string
    if (size < 2) return 0;

    // Create a null-terminated string for the group name
    char group_name[256];
    size_t name_len = (size < 255) ? size : 255;
    memcpy(group_name, data, name_len);
    group_name[name_len] = '\0';

    // Initialize HDF5 library
    hid_t file_id = H5Fcreate("fuzz_test.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Use valid HDF5 identifiers for the creation properties
    hid_t lcpl_id = H5Pcreate(H5P_LINK_CREATE);
    hid_t gcpl_id = H5Pcreate(H5P_GROUP_CREATE);
    hid_t gapl_id = H5Pcreate(H5P_GROUP_ACCESS);

    // Call the function-under-test
    hid_t group_id = H5Gcreate2(file_id, group_name, lcpl_id, gcpl_id, gapl_id);

    // Close the group if it was created successfully
    if (group_id >= 0) {
        H5Gclose(group_id);
    }

    // Close the property lists and file
    H5Pclose(lcpl_id);
    H5Pclose(gcpl_id);
    H5Pclose(gapl_id);
    H5Fclose(file_id);

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

    LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
