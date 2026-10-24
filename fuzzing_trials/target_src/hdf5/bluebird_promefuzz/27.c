#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/hdf5/src/H5Dpublic.h"
#include "/src/hdf5/src/H5Fpublic.h"
#include "/src/hdf5/src/H5Spublic.h"
#include "/src/hdf5/src/H5Tpublic.h"
#include "/src/hdf5/src/H5Ppublic.h"

#define FILENAME "./dummy_file"
#define DATASETNAME "dset"
#define DIM0 4

static void write_dummy_file() {
    FILE *file = fopen(FILENAME, "w");
    if (file) {
        fprintf(file, "dummy data");
        fclose(file);
    }
}

static hid_t create_dataspace() {
    hsize_t dims[1] = {DIM0};
    return H5Screate_simple(1, dims, NULL);
}

int LLVMFuzzerTestOneInput_27(const uint8_t *Data, size_t Size) {
    write_dummy_file();

    hid_t file_id, dset_id, space_id;
    herr_t status;
    haddr_t offset;
    int data[DIM0] = {0, 1, 2, 3};

    // Create a new file using default properties
    file_id = H5Fcreate(FILENAME, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Create the data space
    space_id = create_dataspace();
    if (space_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Create a dataset
    dset_id = H5Dcreate2(file_id, DATASETNAME, H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dset_id < 0) {
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }

    // Get offset
    offset = H5Dget_offset(dset_id);

    // Write data to the dataset
    status = H5Dwrite(dset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, data);

    // Get offset again
    offset = H5Dget_offset(dset_id);

    // Close the dataset
    status = H5Dclose(dset_id);

    // Close the file
    status = H5Fclose(file_id);

    // Open the file
    file_id = H5Fopen(FILENAME, H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Open the dataset
    dset_id = H5Dopen2(file_id, DATASETNAME, H5P_DEFAULT);
    if (dset_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Read data from the dataset
    status = H5Dread(dset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, data);

    // Close the dataset
    status = H5Dclose(dset_id);

    // Close the file
    status = H5Fclose(file_id);

    // Recreate the file
    file_id = H5Fcreate(FILENAME, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Create the dataset again
    dset_id = H5Dcreate2(file_id, DATASETNAME, H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dset_id < 0) {
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }

    // Write data again
    status = H5Dwrite(dset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, data);

    // Close the dataset
    status = H5Dclose(dset_id);

    // Open the dataset
    dset_id = H5Dopen2(file_id, DATASETNAME, H5P_DEFAULT);
    if (dset_id < 0) {
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }

    // Read data again
    status = H5Dread(dset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, data);

    // Close the dataset
    status = H5Dclose(dset_id);

    // Close the file
    status = H5Fclose(file_id);

    // Clean up
    H5Sclose(space_id);

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

    LLVMFuzzerTestOneInput_27(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
