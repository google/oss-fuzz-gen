// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fis_hdf5 at H5Fdeprec.c:144:1 in H5Fpublic.h
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fis_hdf5 at H5Fdeprec.c:144:1 in H5Fpublic.h
// H5Fis_hdf5 at H5Fdeprec.c:144:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "H5Fpublic.h"
#include "H5Ppublic.h" // Include for H5P_DEFAULT

static void write_dummy_file(const char *filename) {
    FILE *file = fopen(filename, "w");
    if (file) {
        fprintf(file, "Dummy HDF5 content");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_42(const uint8_t *Data, size_t Size) {
    const char *filename = "./dummy_file";
    write_dummy_file(filename);

    // Initialize variables for HDF5 operations
    hid_t file_id;
    herr_t status;
    htri_t is_hdf5;

    // First H5Fcreate call
    file_id = H5Fcreate(filename, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id >= 0) {
        // First H5Fclose call
        status = H5Fclose(file_id);
    }

    // Second H5Fclose call (should handle gracefully even if file_id is invalid)
    status = H5Fclose(file_id);

    // First H5Fis_hdf5 call
    is_hdf5 = H5Fis_hdf5(filename);

    // Second H5Fcreate call
    file_id = H5Fcreate(filename, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id >= 0) {
        // Second H5Fclose call
        status = H5Fclose(file_id);
    }

    // Second and third H5Fis_hdf5 calls
    is_hdf5 = H5Fis_hdf5(filename);
    is_hdf5 = H5Fis_hdf5(filename);

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

        LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    