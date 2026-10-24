// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dwrite_multi at H5D.c:1419:1 in H5Dpublic.h
// H5Dread_multi at H5D.c:1109:1 in H5Dpublic.h
// H5Dwrite at H5D.c:1350:1 in H5Dpublic.h
// H5Dread at H5D.c:1041:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "H5Fpublic.h"
#include "H5Dpublic.h"
#include "H5Ppublic.h"
#include "H5Tpublic.h"
#include "H5Spublic.h"

#define FILENAME "./dummy_file"
#define DATASETNAME1 "dset1"
#define DATASETNAME2 "dset2"
#define DIM0 4
#define DIM1 6

static void write_dummy_data(const char *filename) {
    FILE *file = fopen(filename, "w");
    if (file) {
        fprintf(file, "dummy data");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size) {
    hid_t file_id, dset_id1, dset_id2;
    hid_t space_id, type_id;
    herr_t status;
    hsize_t dims[2] = {DIM0, DIM1};
    int data[DIM0][DIM1];
    int read_data[DIM0][DIM1];
    const void *write_bufs[2] = {data, data};
    void *read_bufs[2] = {read_data, read_data};
    hid_t dset_ids[2], mem_type_ids[2], mem_space_ids[2], file_space_ids[2];

    // Initialize data
    for (int i = 0; i < DIM0; i++) {
        for (int j = 0; j < DIM1; j++) {
            data[i][j] = i * DIM1 + j;
        }
    }

    // Write dummy data to file
    write_dummy_data(FILENAME);

    // Create HDF5 file
    file_id = H5Fcreate(FILENAME, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Create dataspace and datatype
    space_id = H5Screate_simple(2, dims, NULL);
    type_id = H5T_NATIVE_INT;

    // Create two datasets
    dset_id1 = H5Dcreate2(file_id, DATASETNAME1, type_id, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dset_id1 < 0) goto close_file;
    
    dset_id2 = H5Dcreate2(file_id, DATASETNAME2, type_id, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dset_id2 < 0) goto close_dset1;

    // Prepare arrays for multi operations
    dset_ids[0] = dset_id1;
    dset_ids[1] = dset_id2;
    mem_type_ids[0] = type_id;
    mem_type_ids[1] = type_id;
    mem_space_ids[0] = space_id;
    mem_space_ids[1] = space_id;
    file_space_ids[0] = space_id;
    file_space_ids[1] = space_id;

    // Write to datasets
    status = H5Dwrite_multi(2, dset_ids, mem_type_ids, mem_space_ids, file_space_ids, H5P_DEFAULT, write_bufs);
    if (status < 0) goto close_dset2;

    // Read from datasets
    status = H5Dread_multi(2, dset_ids, mem_type_ids, mem_space_ids, file_space_ids, H5P_DEFAULT, read_bufs);
    if (status < 0) goto close_dset2;

    // Write to a single dataset
    status = H5Dwrite(dset_id1, type_id, space_id, space_id, H5P_DEFAULT, data);
    if (status < 0) goto close_dset2;

    // Read from a single dataset
    status = H5Dread(dset_id1, type_id, space_id, space_id, H5P_DEFAULT, read_data);
    if (status < 0) goto close_dset2;

close_dset2:
    H5Dclose(dset_id2);
close_dset1:
    H5Dclose(dset_id1);
close_file:
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

        LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    