#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    hid_t group_id = H5I_INVALID_HID; // Invalid ID to start with
    hsize_t num_objs = 0;

    // Create a temporary HDF5 file and group to use for fuzzing
    hid_t file_id = H5Fcreate("temp_fuzz_file.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0; // Failed to create file, exit early
    }

    group_id = H5Gcreate(file_id, "/fuzz_group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        H5Fclose(file_id);
        return 0; // Failed to create group, exit early
    }

    // Call the function-under-test
    herr_t status = H5Gget_num_objs(group_id, &num_objs);

    // Close the group and file
    H5Gclose(group_id);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_32(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
