#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_45(const uint8_t *data, size_t size) {
    hid_t file_id = -1;
    hid_t group_id;
    hid_t lcpl_id = H5P_DEFAULT;
    hid_t gcpl_id = H5P_DEFAULT;
    hid_t gapl_id = H5P_DEFAULT;
    char group_name[256];

    // Ensure there's enough data to create a valid group name
    if (size < 1 || size > 255) {
        return 0;
    }

    // Copy data into group_name and null-terminate it
    memcpy(group_name, data, size);
    group_name[size] = '\0';

    // Create a temporary HDF5 file for testing
    file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Call the function-under-test
    group_id = H5Gcreate2(file_id, group_name, lcpl_id, gcpl_id, gapl_id);

    // Close the group if it was successfully created
    if (group_id >= 0) {
        H5Gclose(group_id);
    }

    // Close the file
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

    LLVMFuzzerTestOneInput_45(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
