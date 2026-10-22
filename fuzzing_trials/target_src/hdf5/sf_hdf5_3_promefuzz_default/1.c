// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fget_mdc_logging_status at H5F.c:2364:1 in H5Fpublic.h
// H5Fstart_mdc_logging at H5F.c:2292:1 in H5Fpublic.h
// H5Fget_mdc_logging_status at H5F.c:2364:1 in H5Fpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fstop_mdc_logging at H5F.c:2328:1 in H5Fpublic.h
// H5Fget_mdc_logging_status at H5F.c:2364:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "H5Fpublic.h"
#include "H5Gpublic.h"
#include <stdbool.h>

#define H5P_DEFAULT 0  // Assuming H5P_DEFAULT is defined as 0 in the actual HDF5 library

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fputs("Dummy data for HDF5 file.", file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_1(const uint8_t *Data, size_t Size) {
    write_dummy_file();

    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    bool is_enabled, is_currently_logging;
    herr_t status = H5Fget_mdc_logging_status(file_id, &is_enabled, &is_currently_logging);
    if (status < 0) goto cleanup_file;

    status = H5Fstart_mdc_logging(file_id);
    if (status < 0) goto cleanup_file;

    status = H5Fget_mdc_logging_status(file_id, &is_enabled, &is_currently_logging);
    if (status < 0) goto cleanup_file;

    hid_t group_id = H5Gcreate2(file_id, "my_group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) goto cleanup_file;

    status = H5Gclose(group_id);
    if (status < 0) goto cleanup_file;

    status = H5Fstop_mdc_logging(file_id);
    if (status < 0) goto cleanup_file;

    status = H5Fget_mdc_logging_status(file_id, &is_enabled, &is_currently_logging);
    if (status < 0) goto cleanup_file;

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

        LLVMFuzzerTestOneInput_1(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    