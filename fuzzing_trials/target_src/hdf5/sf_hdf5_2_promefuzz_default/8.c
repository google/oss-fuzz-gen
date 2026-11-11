// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dwrite at H5D.c:1350:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Dvlen_get_buf_size at H5D.c:1889:1 in H5Dpublic.h
// H5Dread at H5D.c:1041:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "H5Fpublic.h"
#include "H5Dpublic.h"
#include "H5Ppublic.h"
#include "H5Tpublic.h"
#include "H5Spublic.h"

#define FILENAME "./dummy_file"
#define DATASETNAME "dset"

static void write_dummy_file() {
    FILE *file = fopen(FILENAME, "w");
    if (file) {
        fprintf(file, "dummy data");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return 0; // Ensure there's enough data

    write_dummy_file();

    hid_t file_id, dset_id, space_id;
    herr_t status;
    hsize_t dims[1] = {10};
    int buffer[10] = {0};

    // Create a new file using default properties.
    file_id = H5Fcreate(FILENAME, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Create the data space for the dataset.
    space_id = H5Screate_simple(1, dims, NULL);
    if (space_id < 0) goto cleanup_file;

    // Create the dataset with default properties.
    dset_id = H5Dcreate2(file_id, DATASETNAME, H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dset_id < 0) goto cleanup_space;

    // Write the dataset.
    status = H5Dwrite(dset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, buffer);
    if (status < 0) goto cleanup_dataset;

    // Close the dataset.
    H5Dclose(dset_id);

    // Close the file.
    H5Fclose(file_id);

    // Reopen the file and dataset.
    file_id = H5Fopen(FILENAME, H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) return 0;

    dset_id = H5Dopen2(file_id, DATASETNAME, H5P_DEFAULT);
    if (dset_id < 0) goto cleanup_file;

    // Get the size of the buffer needed for VL data.
    hsize_t size_needed;
    status = H5Dvlen_get_buf_size(dset_id, H5T_NATIVE_INT, H5S_ALL, &size_needed);
    if (status < 0) goto cleanup_dataset;

    // Read the dataset.
    status = H5Dread(dset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, buffer);
    if (status < 0) goto cleanup_dataset;

    // Close the dataset.
    H5Dclose(dset_id);

    // Close the file.
    H5Fclose(file_id);

    return 0;

cleanup_dataset:
    H5Dclose(dset_id);
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

        LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    