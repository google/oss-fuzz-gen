#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_40(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for our needs
    if (size < 5) {
        return 0;
    }

    // Initialize the HDF5 library
    H5open();

    // Create a temporary file to work with
    hid_t file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Use the first byte of data to determine a group name length
    size_t group_name_len = data[0] % (size - 1) + 1; // Ensure it's at least 1 and within bounds

    // Allocate memory for the group name
    char *group_name = (char *)malloc(group_name_len + 1);
    if (!group_name) {
        H5Fclose(file_id);
        return 0;
    }

    // Copy the data into the group name and null-terminate it
    for (size_t i = 0; i < group_name_len; i++) {
        group_name[i] = (char)data[i + 1];
    }
    group_name[group_name_len] = '\0';

    // Extract the remaining bytes for the hid_t parameters
    hid_t lcpl_id = (hid_t)data[1];
    hid_t gcpl_id = (hid_t)data[2];
    hid_t gapl_id = (hid_t)data[3];

    // Call the function-under-test
    hid_t group_id = H5Gcreate2(file_id, group_name, lcpl_id, gcpl_id, gapl_id);

    // Clean up
    if (group_id >= 0) {
        H5Gclose(group_id);
    }
    free(group_name);
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

    LLVMFuzzerTestOneInput_40(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
