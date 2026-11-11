#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "hdf5.h"

// Dummy iterator function for H5Giterate
herr_t dummy_iterate(hid_t group, const char *name, void *op_data) {
    // Do nothing, just return success
    return 0;
}

int LLVMFuzzerTestOneInput_48(const uint8_t *data, size_t size) {
    // Initialize variables
    hid_t file_id;
    const char *group_name = "fuzz_group";
    int idx = 0;
    void *op_data = NULL;

    // Create a new HDF5 file using default properties
    file_id = H5Fcreate("fuzz_test.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0; // Failed to create file, exit
    }

    // Create a group in the file
    hid_t group_id = H5Gcreate(file_id, group_name, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        H5Fclose(file_id);
        return 0; // Failed to create group, exit
    }

    // Use the input data to perform some operation, ensuring it's not null
    if (size > 0) {
        // For example, use the first byte of data to decide something
        idx = data[0] % 10; // Just a dummy operation using input data
    }

    // Call the function-under-test
    H5Giterate(group_id, group_name, &idx, dummy_iterate, op_data);

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_48(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
