#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>
#include <string.h>

int LLVMFuzzerTestOneInput_29(const uint8_t *data, size_t size) {
    // Ensure that the data size is sufficient for creating strings and IDs
    if (size < 10) {
        return 0;
    }

    // Create a temporary file to work with HDF5
    hid_t file_id = H5Fcreate("temp_file.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Use parts of the input data to create a group name
    size_t group_name_len = size / 2;
    char *group_name = (char *)malloc(group_name_len + 1);
    if (group_name == NULL) {
        H5Fclose(file_id);
        return 0;
    }
    memcpy(group_name, data, group_name_len);
    group_name[group_name_len] = '\0';

    // Use the rest of the data to create other IDs (simulated as random values)
    hid_t lcpl_id = (hid_t)data[group_name_len] + 1; // Ensure non-zero
    hid_t gcpl_id = (hid_t)data[group_name_len + 1] + 1; // Ensure non-zero
    hid_t gapl_id = (hid_t)data[group_name_len + 2] + 1; // Ensure non-zero

    // Call the function-under-test
    hid_t group_id = H5Gcreate2(file_id, group_name, lcpl_id, gcpl_id, gapl_id);

    // Clean up
    if (group_id >= 0) {
        H5Gclose(group_id);
    }
    free(group_name);
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

    LLVMFuzzerTestOneInput_29(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
