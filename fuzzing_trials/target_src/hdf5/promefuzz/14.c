// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fget_mdc_logging_status at H5F.c:2364:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fstart_mdc_logging at H5F.c:2292:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fget_mdc_logging_status at H5F.c:2364:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fstop_mdc_logging at H5F.c:2328:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fget_mdc_logging_status at H5F.c:2364:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <H5Fpublic.h>
#include <H5Ppublic.h>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Ensure there's at least some data

    // Write data to a dummy file
    write_dummy_file(Data, Size);

    // Create an HDF5 file
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0; // If file creation fails, return

    // Check metadata cache logging status
    bool is_enabled, is_currently_logging;
    if (H5Fget_mdc_logging_status(file_id, &is_enabled, &is_currently_logging) < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Start metadata cache logging
    if (H5Fstart_mdc_logging(file_id) < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Check metadata cache logging status again
    if (H5Fget_mdc_logging_status(file_id, &is_enabled, &is_currently_logging) < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Stop metadata cache logging
    if (H5Fstop_mdc_logging(file_id) < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Final check of metadata cache logging status
    if (H5Fget_mdc_logging_status(file_id, &is_enabled, &is_currently_logging) < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Close the HDF5 file
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

        LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    