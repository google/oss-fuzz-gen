#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_74(const uint8_t *data, size_t size) {
    // Initialize HDF5 library
    H5open();

    // Declare variables at the beginning
    hid_t file_id, dataspace_id, attr_id;
    herr_t status;
    hsize_t dims[1] = {10};

    // Create a file to work with
    file_id = H5Fcreate("fuzz_test_file.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) goto cleanup;

    // Create a dataspace
    dataspace_id = H5Screate_simple(1, dims, NULL);
    if (dataspace_id < 0) goto cleanup_file;

    // Create an attribute
    attr_id = H5Acreate2(file_id, "fuzz_attribute", H5T_NATIVE_INT, dataspace_id, H5P_DEFAULT, H5P_DEFAULT);
    if (attr_id < 0) goto cleanup_dataspace;

    // Ensure data is not NULL
    if (size == 0) goto cleanup_attr;

    // Call the function-under-test
    status = H5Awrite(attr_id, H5T_NATIVE_INT, data);

cleanup_attr:
    H5Aclose(attr_id);
cleanup_dataspace:
    H5Sclose(dataspace_id);
cleanup_file:
    H5Fclose(file_id);
cleanup:
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_74(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
