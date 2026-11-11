// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fget_mdc_hit_rate at H5F.c:1853:1 in H5Fpublic.h
// H5Freset_mdc_hit_rate_stats at H5F.c:1947:1 in H5Fpublic.h
// H5Fget_mdc_size at H5F.c:1895:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fdelete at H5F.c:1117:1 in H5Fpublic.h
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fget_mdc_config at H5F.c:1772:1 in H5Fpublic.h
// H5Fset_mdc_config at H5F.c:1814:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <H5Fpublic.h>
#include <H5Ppublic.h>

static H5AC_cache_config_t generate_random_config(const uint8_t *Data, size_t Size) {
    H5AC_cache_config_t config;
    memset(&config, 0, sizeof(H5AC_cache_config_t));
    config.version = H5AC__CURR_CACHE_CONFIG_VERSION;
    if (Size > 0) {
        config.rpt_fcn_enabled = Data[0] % 2;
        config.open_trace_file = Data[0] % 2;
        config.close_trace_file = Data[0] % 2;
        config.evictions_enabled = Data[0] % 2;
        config.set_initial_size = Data[0] % 2;
    }
    if (Size > 8) {
        config.initial_size = *(size_t *)(Data + 1);
        config.min_clean_fraction = (double)Data[5] / 255.0;
        config.max_size = *(size_t *)(Data + 6);
        config.min_size = *(size_t *)(Data + 10);
        config.epoch_length = *(long int *)(Data + 14);
        config.incr_mode = (enum H5C_cache_incr_mode)(Data[18] % 2);
        config.lower_hr_threshold = (double)Data[19] / 255.0;
        config.increment = (double)Data[20] / 255.0 + 1.0;
        config.apply_max_increment = Data[21] % 2;
        config.max_increment = *(size_t *)(Data + 22);
        config.flash_incr_mode = (enum H5C_cache_flash_incr_mode)(Data[26] % 2);
        config.flash_multiple = (double)Data[27] / 255.0;
        config.flash_threshold = (double)Data[28] / 255.0;
        config.decr_mode = (enum H5C_cache_decr_mode)(Data[29] % 4);
        config.upper_hr_threshold = (double)Data[30] / 255.0;
        config.decrement = (double)Data[31] / 255.0;
        config.apply_max_decrement = Data[32] % 2;
        config.max_decrement = *(size_t *)(Data + 33);
        config.epochs_before_eviction = Data[37];
        config.apply_empty_reserve = Data[38] % 2;
        config.empty_reserve = (double)Data[39] / 255.0;
        config.dirty_bytes_threshold = *(size_t *)(Data + 40);
        config.metadata_write_strategy = Data[44] % 2;
    } else {
        config.initial_size = 1024;
        config.min_clean_fraction = 0.1;
        config.max_size = 1024 * 1024;
        config.min_size = 512;
        config.epoch_length = 50000;
        config.incr_mode = H5C_incr__threshold;
        config.lower_hr_threshold = 0.8;
        config.increment = 2.0;
        config.apply_max_increment = 1;
        config.max_increment = 1024 * 1024;
        config.flash_incr_mode = H5C_flash_incr__add_space;
        config.flash_multiple = 0.1;
        config.flash_threshold = 0.1;
        config.decr_mode = H5C_decr__threshold;
        config.upper_hr_threshold = 0.9995;
        config.decrement = 0.9;
        config.apply_max_decrement = 1;
        config.max_decrement = 1024 * 1024;
        config.epochs_before_eviction = 3;
        config.apply_empty_reserve = 1;
        config.empty_reserve = 0.1;
        config.dirty_bytes_threshold = 256 * 1024;
        config.metadata_write_strategy = H5AC_METADATA_WRITE_STRATEGY__PROCESS_0_ONLY;
    }
    return config;
}

int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size) {
    hid_t file_id;
    herr_t status;
    double hit_rate;
    size_t max_size, min_clean_size, cur_size;
    int cur_num_entries;
    H5AC_cache_config_t config;

    // Step 1: Create a new HDF5 file
    file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Step 2: Get metadata cache configurations
    config = generate_random_config(Data, Size);
    for (int i = 0; i < 4; i++) {
        status = H5Fget_mdc_config(file_id, &config);
        if (status < 0) break;
    }

    // Step 3: Set metadata cache configurations
    for (int i = 0; i < 4; i++) {
        status = H5Fset_mdc_config(file_id, &config);
        if (status < 0) break;
    }

    // Step 4: Get metadata cache hit rate
    for (int i = 0; i < 2; i++) {
        status = H5Fget_mdc_hit_rate(file_id, &hit_rate);
        if (status < 0) break;
    }

    // Step 5: Reset metadata cache hit rate statistics
    for (int i = 0; i < 2; i++) {
        status = H5Freset_mdc_hit_rate_stats(file_id);
        if (status < 0) break;
    }

    // Step 6: Get metadata cache size
    for (int i = 0; i < 6; i++) {
        status = H5Fget_mdc_size(file_id, &max_size, &min_clean_size, &cur_size, &cur_num_entries);
        if (status < 0) break;
    }

    // Step 7: Close the file
    status = H5Fclose(file_id);
    if (status < 0) return 0;

    // Step 8: Delete the file
    status = H5Fdelete("./dummy_file", H5P_DEFAULT);

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

        LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    