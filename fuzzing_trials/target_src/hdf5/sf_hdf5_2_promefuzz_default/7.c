// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dwrite at H5D.c:1350:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dread at H5D.c:1041:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "H5Fpublic.h"
#include "H5Dpublic.h"
#include "H5Spublic.h"
#include "H5Tpublic.h"
#include "H5Ppublic.h"

#define FILENAME "./dummy_file"
#define DATASETNAME "DS1"
#define DATA_SIZE 1024

static void write_dummy_data(const char *filename) {
    FILE *file = fopen(filename, "wb");
    if (file) {
        uint8_t data[DATA_SIZE] = {0};
        fwrite(data, 1, DATA_SIZE, file);
        fclose(file);
    }
}

static herr_t test_hdf5_operations(hid_t file_id) {
    hid_t space_id = H5Screate(H5S_SCALAR);
    if (space_id < 0) return -1;

    hid_t dset_id = H5Dcreate2(file_id, DATASETNAME, H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dset_id < 0) {
        H5Sclose(space_id);
        return -1;
    }

    int data = 42;
    herr_t status = H5Dwrite(dset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, &data);
    if (status < 0) {
        H5Dclose(dset_id);
        H5Sclose(space_id);
        return -1;
    }

    H5Dclose(dset_id);
    H5Sclose(space_id);
    return 0;
}

int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size) {
    write_dummy_data(FILENAME);

    hid_t file_id = H5Fcreate(FILENAME, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    if (test_hdf5_operations(file_id) < 0) {
        H5Fclose(file_id);
        return 0;
    }

    H5Fclose(file_id);

    file_id = H5Fopen(FILENAME, H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) return 0;

    hid_t dset_id = H5Dopen2(file_id, DATASETNAME, H5P_DEFAULT);
    if (dset_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    int data;
    herr_t status = H5Dread(dset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, &data);
    if (status < 0) {
        H5Dclose(dset_id);
        H5Fclose(file_id);
        return 0;
    }

    H5Dclose(dset_id);
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

        LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    