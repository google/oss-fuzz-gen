#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_42(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for our needs
    if (size < 3) {
        return 0;
    }

    // Initialize HDF5 library
    H5open();

    // Create a temporary file to work with
    hid_t file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Use the first byte of data to determine a group name length
    size_t group_name_length = data[0] % (size - 1) + 1; // Ensure it's at least 1
    char *group_name = (char *)malloc(group_name_length + 1);
    if (group_name == NULL) {
        H5Fclose(file_id);
        return 0;
    }

    // Copy the group name from data
    for (size_t i = 0; i < group_name_length; i++) {
        group_name[i] = (char)(data[i + 1] % 26 + 'A'); // Create a simple name
    }
    group_name[group_name_length] = '\0';

    // Use remaining data to determine property lists
    hid_t lcpl_id = (hid_t)(data[group_name_length + 1] % 2 ? H5P_DEFAULT : H5P_DEFAULT);
    hid_t gcpl_id = (hid_t)(data[group_name_length + 2] % 2 ? H5P_DEFAULT : H5P_DEFAULT);
    hid_t gapl_id = (hid_t)(data[group_name_length + 3] % 2 ? H5P_DEFAULT : H5P_DEFAULT);

    // Call the function-under-test
    hid_t group_id = H5Gcreate2(file_id, group_name, lcpl_id, gcpl_id, gapl_id);

    // Clean up
    if (group_id >= 0) {
        H5Gclose(group_id);
    }
    free(group_name);
    H5Fclose(file_id);

    // Close HDF5 library
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

    LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
