#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_31(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    hid_t loc_id = H5I_INVALID_HID;
    hid_t type_id = H5I_INVALID_HID;
    hid_t space_id = H5I_INVALID_HID;
    hid_t lcpl_id = H5P_DEFAULT;
    hid_t dcpl_id = H5P_DEFAULT;
    hid_t dapl_id = H5P_DEFAULT;
    char name[256];

    // Ensure data size is sufficient for creating a name
    if (size < 1) {
        return 0;
    }

    // Create a temporary file to use as the HDF5 file
    char tmpl[] = "/tmp/hdf5fuzzXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    close(fd);

    // Create an HDF5 file and get a file identifier
    loc_id = H5Fcreate(tmpl, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (loc_id < 0) {
        unlink(tmpl);
        return 0;
    }

    // Copy data into name, ensuring null-termination
    size_t name_len = size < sizeof(name) ? size : sizeof(name) - 1;
    memcpy(name, data, name_len);
    name[name_len] = '\0';

    // Create a simple dataspace
    hsize_t dims[1] = {10};
    space_id = H5Screate_simple(1, dims, NULL);
    if (space_id < 0) {
        H5Fclose(loc_id);
        unlink(tmpl);
        return 0;
    }

    // Use a predefined datatype for simplicity
    type_id = H5T_NATIVE_INT;

    // Call the function-under-test
    hid_t dataset_id = H5Dcreate2(loc_id, name, type_id, space_id, lcpl_id, dcpl_id, dapl_id);

    // Clean up resources
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }
    H5Sclose(space_id);
    H5Fclose(loc_id);
    unlink(tmpl);

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

    LLVMFuzzerTestOneInput_31(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
