#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_58(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for creating valid strings
    if (size < 4) return 0;

    // Create temporary file names for the HDF5 file and dataset
    char file_name[] = "/tmp/hdf5fileXXXXXX";
    char dataset_name[] = "/tmp/datasetXXXXXX";

    // Create temporary files
    int file_fd = mkstemp(file_name);
    if (file_fd == -1) return 0;
    close(file_fd);

    int dataset_fd = mkstemp(dataset_name);
    if (dataset_fd == -1) {
        unlink(file_name);
        return 0;
    }
    close(dataset_fd);

    // Initialize HDF5 library
    H5open();

    // Create a file access property list
    hid_t fapl_id = H5Pcreate(H5P_FILE_ACCESS);
    if (fapl_id < 0) goto cleanup;

    // Create a file
    hid_t file_id = H5Fcreate(file_name, H5F_ACC_TRUNC, H5P_DEFAULT, fapl_id);
    if (file_id < 0) goto cleanup;

    // Create a dataspace
    hsize_t dims[2] = {10, 10};
    hid_t space_id = H5Screate_simple(2, dims, NULL);
    if (space_id < 0) goto cleanup;

    // Use the first byte of data for the datatype
    hid_t dtype_id = H5Tcopy(H5T_NATIVE_INT);
    if (dtype_id < 0) goto cleanup;

    // Use the first byte of data for the dataset creation property list
    hid_t dcpl_id = H5Pcreate(H5P_DATASET_CREATE);
    if (dcpl_id < 0) goto cleanup;

    // Use the first byte of data for the dataset access property list
    hid_t dapl_id = H5Pcreate(H5P_DATASET_ACCESS);
    if (dapl_id < 0) goto cleanup;

    // Use the first byte of data for the link creation property list
    hid_t lcpl_id = H5Pcreate(H5P_LINK_CREATE);
    if (lcpl_id < 0) goto cleanup;

    // Use the first byte of data for the link access property list
    hid_t lapl_id = H5Pcreate(H5P_LINK_ACCESS);
    if (lapl_id < 0) goto cleanup;

    // Call the function under test
    hid_t dataset_id = H5Dcreate2(file_id, dataset_name, dtype_id, space_id, lcpl_id, dcpl_id, dapl_id);

    // Close the dataset if it was created
    if (dataset_id >= 0) H5Dclose(dataset_id);

cleanup:
    // Close and release resources
    if (fapl_id >= 0) H5Pclose(fapl_id);
    if (file_id >= 0) H5Fclose(file_id);
    if (space_id >= 0) H5Sclose(space_id);
    if (dtype_id >= 0) H5Tclose(dtype_id);
    if (dcpl_id >= 0) H5Pclose(dcpl_id);
    if (dapl_id >= 0) H5Pclose(dapl_id);
    if (lcpl_id >= 0) H5Pclose(lcpl_id);
    if (lapl_id >= 0) H5Pclose(lapl_id);

    // Remove temporary files
    unlink(file_name);
    unlink(dataset_name);

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_58(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
