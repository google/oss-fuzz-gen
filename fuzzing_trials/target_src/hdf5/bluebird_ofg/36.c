#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "hdf5.h"

int LLVMFuzzerTestOneInput_36(const uint8_t *data, size_t size) {
    hid_t file_id = -1;
    hid_t dataset_id = -1;
    hid_t dataspace_id = -1;
    int num_attrs = -1;

    // Create a temporary HDF5 file
    file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) goto cleanup;

    // Create a simple dataset within the file
    hsize_t dims[1] = {10};
    dataspace_id = H5Screate_simple(1, dims, NULL);
    if (dataspace_id < 0) goto cleanup;

    dataset_id = H5Dcreate2(file_id, "dset", H5T_NATIVE_INT, dataspace_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dataset_id < 0) goto cleanup;

    // Call the function-under-test
    num_attrs = H5Aget_num_attrs(dataset_id);

cleanup:
    if (dataset_id >= 0) H5Dclose(dataset_id);
    if (file_id >= 0) H5Fclose(file_id);
    if (dataspace_id >= 0) H5Sclose(dataspace_id);

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

    LLVMFuzzerTestOneInput_36(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
