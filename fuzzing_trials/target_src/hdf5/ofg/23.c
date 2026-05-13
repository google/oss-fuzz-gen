#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

// Define the number of metadata read retry types
#define H5F_NUM_METADATA_READ_RETRY_TYPES 21

int LLVMFuzzerTestOneInput_23(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to create a valid HDF5 file
    if (size < 1) {
        return 0;
    }

    // Create a temporary HDF5 file
    hid_t file_id;
    H5F_retry_info_t retry_info;
    char filename[] = "tempfile.h5";

    // Create a new HDF5 file using default properties
    file_id = H5Fcreate(filename, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Initialize retry_info
    retry_info.nbins = 0;
    for (int i = 0; i < H5F_NUM_METADATA_READ_RETRY_TYPES; i++) {
        retry_info.retries[i] = NULL;
    }

    // Call the function-under-test
    if (H5Fget_metadata_read_retry_info(file_id, &retry_info) < 0) {
        H5Fclose(file_id);
        return 0;
    }

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_23(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
