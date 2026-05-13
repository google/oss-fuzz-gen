#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_277(const uint8_t *data, size_t size) {
    // Initialize HDF5 library
    H5open();

    // Ensure the data size is sufficient to create a file name
    if (size < 1) {
        return 0;
    }

    // Create a temporary file name using the input data
    char filename[256];
    snprintf(filename, sizeof(filename), "/tmp/fuzzfile_%d.h5", data[0]);

    // Create a new HDF5 file to obtain a valid hid_t
    hid_t file_id = H5Fcreate(filename, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Initialize the H5AC_cache_config_t structure
    H5AC_cache_config_t config;
    config.version = H5AC__CURR_CACHE_CONFIG_VERSION;

    // Call the function-under-test
    herr_t status = H5Fget_mdc_config(file_id, &config);

    // Close the HDF5 file
    H5Fclose(file_id);

    // Clean up the HDF5 library
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

    LLVMFuzzerTestOneInput_277(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
