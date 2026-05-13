#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "hdf5.h"

// Remove the extern "C" linkage specification as it is not needed in C
int LLVMFuzzerTestOneInput_155(const uint8_t *data, size_t size) {
    // Initialize a hid_t variable
    hid_t file_id = H5I_INVALID_HID; // Use an invalid ID initially

    // Create a temporary file to get a valid hid_t
    const char *filename = "tempfile.h5";
    file_id = H5Fcreate(filename, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0; // Exit if file creation fails
    }

    // Initialize H5AC_cache_config_t with some default values
    H5AC_cache_config_t mdc_config;
    mdc_config.version = H5AC__CURR_CACHE_CONFIG_VERSION;
    mdc_config.rpt_fcn_enabled = 0;
    mdc_config.open_trace_file = 0;
    mdc_config.close_trace_file = 0;
    mdc_config.trace_file_name[0] = '\0';
    mdc_config.evictions_enabled = 1;
    mdc_config.set_initial_size = 0;
    mdc_config.initial_size = 0;
    mdc_config.min_clean_fraction = 0.1;
    mdc_config.max_size = 1024 * 1024;
    mdc_config.min_size = 512 * 1024;
    mdc_config.epoch_length = 50000;

    // Call the function-under-test
    herr_t status = H5Fset_mdc_config(file_id, &mdc_config);

    // Clean up
    H5Fclose(file_id);
    remove(filename);

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

    LLVMFuzzerTestOneInput_155(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
