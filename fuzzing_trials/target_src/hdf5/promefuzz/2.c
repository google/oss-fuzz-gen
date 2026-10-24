// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fset_mdc_config at H5F.c:1814:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dread at H5D.c:1041:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fdelete at H5F.c:1117:1 in H5Fpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fset_mdc_config at H5F.c:1814:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dget_space at H5D.c:597:1 in H5Dpublic.h
// H5Dwrite at H5D.c:1350:1 in H5Dpublic.h
// H5Fset_mdc_config at H5F.c:1814:1 in H5Fpublic.h
// H5Dread at H5D.c:1041:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <hdf5.h>
#include "H5Dpublic.h"
#include "H5Fpublic.h"

#define DUMMY_FILENAME "./dummy_file"
#define DATASET_NAME "dset"

static void initialize_cache_config(H5AC_cache_config_t *config) {
    config->version = H5AC__CURR_CACHE_CONFIG_VERSION;
    config->rpt_fcn_enabled = 0;
    config->open_trace_file = 0;
    config->close_trace_file = 0;
    config->evictions_enabled = 1;
    config->set_initial_size = 0;
    config->initial_size = 0;
    config->min_clean_fraction = 0.1;
    config->max_size = 1024 * 1024;
    config->min_size = 512 * 1024;
    config->epoch_length = 10000;
    config->incr_mode = H5C_incr__threshold;
    config->lower_hr_threshold = 0.9;
    config->increment = 2.0;
    config->apply_max_increment = 1;
    config->max_increment = 1024 * 1024;
    config->flash_incr_mode = H5C_flash_incr__add_space;
    config->flash_multiple = 1.0;
    config->flash_threshold = 0.5;
    config->decr_mode = H5C_decr__age_out_with_threshold;
    config->upper_hr_threshold = 0.999;
    config->decrement = 0.9;
    config->apply_max_decrement = 1;
    config->max_decrement = 1024 * 1024;
    config->epochs_before_eviction = 3;
    config->apply_empty_reserve = 1;
    config->empty_reserve = 0.1;
    config->dirty_bytes_threshold = 256 * 1024;
    config->metadata_write_strategy = H5AC_METADATA_WRITE_STRATEGY__PROCESS_0_ONLY;
}

int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size) {
    hid_t file_id, dset_id, space_id, mem_type_id;
    herr_t status;
    H5AC_cache_config_t cache_config;
    hsize_t dims[1] = {10};
    int data[10] = {0};
    
    // Prepare dummy data from input
    if (Size >= sizeof(data)) {
        memcpy(data, Data, sizeof(data));
    }

    // Initialize cache configuration
    initialize_cache_config(&cache_config);

    // Create a new HDF5 file using default properties
    file_id = H5Fcreate(DUMMY_FILENAME, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Set metadata cache configuration
    status = H5Fset_mdc_config(file_id, &cache_config);
    if (status < 0) goto cleanup_file;

    // Create the data space for the dataset
    space_id = H5Screate_simple(1, dims, NULL);
    if (space_id < 0) goto cleanup_file;

    // Create a dataset
    dset_id = H5Dcreate2(file_id, DATASET_NAME, H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dset_id < 0) goto cleanup_space;

    // Get the dataspace of the dataset
    hid_t space_copy = H5Dget_space(dset_id);
    if (space_copy < 0) goto cleanup_dset;

    // Write the dataset
    status = H5Dwrite(dset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, data);
    if (status < 0) goto cleanup_space_copy;

    // Set metadata cache configuration again
    status = H5Fset_mdc_config(file_id, &cache_config);
    if (status < 0) goto cleanup_space_copy;

    // Read the dataset back
    int read_data[10] = {0};
    status = H5Dread(dset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, read_data);
    if (status < 0) goto cleanup_space_copy;

    // Close the dataset
    status = H5Dclose(dset_id);
    if (status < 0) goto cleanup_space_copy;

    // Set metadata cache configuration once more
    status = H5Fset_mdc_config(file_id, &cache_config);
    if (status < 0) goto cleanup_space_copy;

    // Re-open the dataset and read again
    dset_id = H5Dcreate2(file_id, DATASET_NAME, H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dset_id < 0) goto cleanup_space_copy;

    status = H5Dread(dset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, read_data);
    if (status < 0) goto cleanup_dset;

    // Close the dataset
    status = H5Dclose(dset_id);
    if (status < 0) goto cleanup_space_copy;

    // Close the dataspace copy
    status = H5Sclose(space_copy);
    if (status < 0) goto cleanup_space;

    // Close the dataspace
    status = H5Sclose(space_id);
    if (status < 0) goto cleanup_file;

    // Close the file
    status = H5Fclose(file_id);
    if (status < 0) return 0;

    // Delete the file
    status = H5Fdelete(DUMMY_FILENAME, H5P_DEFAULT);
    if (status < 0) return 0;

    return 0;

cleanup_dset:
    H5Dclose(dset_id);
cleanup_space_copy:
    H5Sclose(space_copy);
cleanup_space:
    H5Sclose(space_id);
cleanup_file:
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

        LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    