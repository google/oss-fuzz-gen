#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for creating a valid string
    if (size < 1) {
        return 0;
    }

    // Create a copy of the data to ensure null-termination for the string
    char *group_name = (char *)malloc(size + 1);
    if (group_name == NULL) {
        return 0;
    }
    memcpy(group_name, data, size);
    group_name[size] = '\0';

    // Initialize HDF5 library
    H5open();

    // Create a file to work with
    hid_t file_id = H5Fcreate("fuzz_test_file.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        free(group_name);
        return 0;
    }

    // Set up property lists (using default properties for simplicity)
    hid_t lcpl_id = H5P_DEFAULT; // Link creation property list
    hid_t gcpl_id = H5P_DEFAULT; // Group creation property list
    hid_t gapl_id = H5P_DEFAULT; // Group access property list

    // Call the function-under-test
    hid_t group_id = H5Gcreate2(file_id, group_name, lcpl_id, gcpl_id, gapl_id);

    // Clean up
    if (group_id >= 0) {
        H5Gclose(group_id);
    }
    H5Fclose(file_id);
    free(group_name);

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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
