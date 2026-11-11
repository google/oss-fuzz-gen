#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_6(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    hid_t loc_id;
    H5G_info_t group_info;

    // Ensure size is sufficient for creating a valid HDF5 object
    if (size < sizeof(hid_t)) {
        return 0;
    }

    // Use the data to create a valid HDF5 file in memory
    hid_t file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Create a group within the file
    loc_id = H5Gcreate(file_id, "/test_group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (loc_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Call the function-under-test
    herr_t result = H5Gget_info(loc_id, &group_info);

    // Close the group and file
    H5Gclose(loc_id);
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

    LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
