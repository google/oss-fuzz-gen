#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>
#include <string.h>
#include <unistd.h> // Include this for mkstemp and unlink

int LLVMFuzzerTestOneInput_38(const uint8_t *data, size_t size) {
    // Initialize HDF5 library
    H5open();

    // Ensure the input size is sufficient for a basic test
    if (size < 10) {
        return 0;
    }

    // Create a temporary file to use as the HDF5 file
    char filename[] = "tempfileXXXXXX";
    int fd = mkstemp(filename);
    if (fd == -1) {
        return 0;
    }
    close(fd);

    // Create an HDF5 file
    hid_t file_id = H5Fcreate(filename, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Extract a group name from the input data
    size_t group_name_length = size > 20 ? 20 : size;
    char group_name[21];
    memcpy(group_name, data, group_name_length);
    group_name[group_name_length] = '\0';

    // Extract additional parameters from the input data
    hid_t lcpl_id = (hid_t)data[0];
    hid_t gcpl_id = (hid_t)data[1];
    hid_t gapl_id = (hid_t)data[2];

    // Call the function-under-test
    hid_t group_id = H5Gcreate2(file_id, group_name, lcpl_id, gcpl_id, gapl_id);

    // Clean up
    if (group_id >= 0) {
        H5Gclose(group_id);
    }
    H5Fclose(file_id);
    unlink(filename);

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

    LLVMFuzzerTestOneInput_38(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
