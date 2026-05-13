#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "hdf5.h"

static herr_t create_and_write_dataset(hid_t file_id, const char *dataset_name, const uint8_t *Data, size_t Size) {
    hid_t space_id = -1, dset_id = -1, mem_space_id = -1;
    herr_t status = -1;
    hsize_t dims[1] = {Size};
    hsize_t maxdims[1] = {H5S_UNLIMITED};
    hsize_t new_size[1] = {Size + 10}; // Arbitrary extension size

    // Create a simple dataspace with unlimited dimensions
    space_id = H5Screate_simple(1, dims, maxdims);
    if (space_id < 0) goto error;

    // Create a dataset creation property list
    hid_t dcpl_id = H5Pcreate(H5P_DATASET_CREATE);
    if (dcpl_id < 0) goto error;

    // Enable chunking
    hsize_t chunk_dims[1] = {10};
    status = H5Pset_chunk(dcpl_id, 1, chunk_dims);
    if (status < 0) goto error;

    // Create the dataset
    dset_id = H5Dcreate2(file_id, dataset_name, H5T_NATIVE_UINT8, space_id, H5P_DEFAULT, dcpl_id, H5P_DEFAULT);
    if (dset_id < 0) goto error;

    // Extend the dataset
    status = H5Dextend(dset_id, new_size);
    if (status < 0) goto error;

    // Write to the dataset
    mem_space_id = H5Screate_simple(1, dims, NULL);
    if (mem_space_id < 0) goto error;

    status = H5Dwrite(dset_id, H5T_NATIVE_UINT8, mem_space_id, H5S_ALL, H5P_DEFAULT, Data);
    if (status < 0) goto error;

    // Read back the data
    uint8_t *read_data = (uint8_t *)malloc(Size);
    if (!read_data) goto error;

    status = H5Dread(dset_id, H5T_NATIVE_UINT8, mem_space_id, H5S_ALL, H5P_DEFAULT, read_data);
    if (status < 0) {
        free(read_data);
        goto error;
    }

    // Clean up
    free(read_data);
    H5Sclose(mem_space_id);
    H5Dclose(dset_id);
    H5Sclose(space_id);
    H5Pclose(dcpl_id);
    return 0;

error:
    if (mem_space_id >= 0) H5Sclose(mem_space_id);
    if (dset_id >= 0) H5Dclose(dset_id);
    if (space_id >= 0) H5Sclose(space_id);
    if (dcpl_id >= 0) H5Pclose(dcpl_id);
    return -1;
}

int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Create a dummy file
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Use the first byte of data as a simple dataset name
    char dataset_name[16];
    snprintf(dataset_name, sizeof(dataset_name), "dset_%02x", Data[0]);

    create_and_write_dataset(file_id, dataset_name, Data, Size);

    // Close the file
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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
